#!/usr/bin/env python3
"""
tests/test_e05_elf_loader.py - Test Suite for E05 (ELF64 / AArch64 Loader & Symbol Resolution)

Covers:
  - Dry-run loading of 4 target Durak 25.0 shared libraries:
    * libsqlite3.so (strict 64 KiB segment alignment verification)
    * libmain.so (16 KiB alignment)
    * libunity.so (16 KiB alignment, .init_array relocation verification)
    * libil2cpp.so (16 KiB alignment, extensive RELA handling)
  - Non-overlapping virtual memory address placement and BSS zero-fill
  - Relocation engine: R_AARCH64_RELATIVE, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_ABS64
  - Synthetic cross-module export/import resolution
  - WEAK symbol resolution (resolves to NULL / addend safely)
  - Strict mode rejection of unresolved STRONG (GLOBAL) symbols
  - W^X page protection compliance (0 violations, PT_GNU_RELRO write stripping)
  - Unresolved imports diagnostic reports (JSON and Markdown)
  - Full suite of negative mutations (corrupt magic, truncated header, wrong class/endianness/machine,
    segment bounds overflow, misaligned vaddr, overlapping PT_LOAD, RWX W^X violation, out-of-bounds reloc)
"""

import unittest
import os
import sys
import tempfile
import struct
import json
import shutil
import subprocess
import hashlib

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_DIR = os.path.join(WORKSPACE_ROOT, "tools")
sys.path.insert(0, TOOLS_DIR)

from elf_loader import (
    ElfModule, MultiModuleLoader, ElfValidationError, UnresolvedSymbolError,
    ELFMAG, ELFCLASS64, ELFCLASS32, ELFDATA2LSB, ELFDATA2MSB, EV_CURRENT,
    ET_DYN, ET_EXEC, EM_AARCH64,
    PT_LOAD, PT_DYNAMIC, PT_GNU_RELRO, PT_NOTE,
    PF_R, PF_W, PF_X,
    DT_NULL, DT_HASH, DT_GNU_HASH, DT_STRTAB, DT_STRSZ, DT_SYMTAB, DT_SYMENT,
    DT_RELA, DT_RELASZ, DT_RELAENT, DT_PLTREL,
    STB_GLOBAL, STB_WEAK, STT_FUNC, SHN_UNDEF, SHN_ABS,
    R_AARCH64_NONE, R_AARCH64_RELATIVE, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_ABS64,
    EXPECTED_PACKAGE, EXPECTED_VERSION_NAME, EXPECTED_VERSION_CODE, EXPECTED_CORE_LIBRARIES,
    verify_durak_default_environment, ANDROID_SHIM_SYMBOLS,
    SORTED_ANDROID_SHIM_SYMBOLS, ANDROID_SHIM_ADDRESSES, resolve_android_shim
)

DATA_DIR = os.path.join(WORKSPACE_ROOT, "extracted_durak")
SQLITE3_PATH = os.path.join(DATA_DIR, "libsqlite3.so")
MAIN_PATH = os.path.join(DATA_DIR, "libmain.so")
UNITY_PATH = os.path.join(DATA_DIR, "libunity.so")
IL2CPP_PATH = os.path.join(DATA_DIR, "libil2cpp.so")


def build_synthetic_elf(p_flags=PF_R | PF_X, p_vaddr=0x1000, p_offset=0x1000,
                        p_filesz=0x100, p_memsz=0x200, p_align=0x1000,
                        e_type=ET_DYN, e_machine=EM_AARCH64, e_ident=None,
                        phentsize=56, phnum=1, total_file_size=None,
                        extra_segments=None) -> bytes:
    """Builds a synthetic ELF64 / AArch64 binary for negative & boundary testing."""
    if e_ident is None:
        ident_bytes = ELFMAG + bytes([ELFCLASS64, ELFDATA2LSB, EV_CURRENT, 0]) + b'\x00' * 8
    else:
        ident_bytes = e_ident

    ehdr = struct.pack(
        '<16sHHIQQQIHHHHHH',
        ident_bytes,
        e_type, e_machine, 1, 0, 64, 0, 0, 64, phentsize, phnum, 64, 0, 0
    )

    phdrs = bytearray()
    if phnum > 0 and phentsize == 56:
        phdrs += struct.pack('<IIQQQQQQ', PT_LOAD, p_flags, p_offset, p_vaddr, p_vaddr, p_filesz, p_memsz, p_align)
        if extra_segments:
            for seg in extra_segments:
                phdrs += struct.pack('<IIQQQQQQ', *seg)

    needed_size = max(64 + len(phdrs), p_offset + p_filesz)
    if extra_segments:
        for seg in extra_segments:
            needed_size = max(needed_size, seg[2] + seg[5])

    final_size = total_file_size if total_file_size is not None else needed_size
    data = bytearray(final_size)
    data[:len(ehdr)] = ehdr
    if len(phdrs) > 0 and len(data) >= 64 + len(phdrs):
        data[64:64 + len(phdrs)] = phdrs

    return bytes(data)


def build_dynamic_elf(exports=None, imports=None, is_weak=False,
                       custom_strsz=None, omit_strsz=False, dt_needed=None,
                       corrupt_symbol_strtab_nul=False, corrupt_needed_strtab_nul=False) -> bytes:
    """
    Builds a valid dynamic ELF64 / AArch64 shared library with PT_LOAD, PT_DYNAMIC,
    symbol table, string table, SysV DT_HASH, and RELA table for cross-module linking tests.
    """
    exports = exports or []
    imports = imports or []

    strtab = bytearray(b'\x00')
    symtab = struct.pack('<IBBHQQ', 0, 0, 0, 0, 0, 0)  # Symbol 0 dummy

    for item in exports:
        if len(item) == 2:
            sym_name, sym_val = item
            shndx = 1
            bind = STB_GLOBAL
        elif len(item) == 3:
            sym_name, sym_val, shndx = item
            bind = STB_GLOBAL
        else:
            sym_name, sym_val, shndx, bind = item
        s_off = len(strtab)
        if corrupt_symbol_strtab_nul:
            strtab += sym_name.encode()
        else:
            strtab += sym_name.encode() + b'\x00'
        st_info = (bind << 4) | STT_FUNC
        symtab += struct.pack('<IBBHQQ', s_off, st_info, 0, shndx, sym_val, 0x20)

    relas = b''
    for i, (sym_name, rel_type, rel_target, addend) in enumerate(imports, start=len(exports) + 1):
        s_off = len(strtab)
        strtab += sym_name.encode() + b'\x00'
        bind = STB_WEAK if is_weak else STB_GLOBAL
        st_info = (bind << 4) | STT_FUNC
        symtab += struct.pack('<IBBHQQ', s_off, st_info, 0, SHN_UNDEF, 0, 0)
        r_info = (i << 32) | rel_type
        relas += struct.pack('<QQq', rel_target, r_info, addend)

    num_symbols = 1 + len(exports) + len(imports)
    # SysV DT_HASH: nbucket=1, nchain=num_symbols, bucket[1], chain[num_symbols]
    hash_bytes = struct.pack('<II', 1, num_symbols) + struct.pack('<I', 0) + struct.pack(f'<{num_symbols}I', *([0] * num_symbols))

    needed_entries = []
    if dt_needed:
        for n in dt_needed:
            if isinstance(n, str):
                s_off = len(strtab)
                if corrupt_needed_strtab_nul:
                    strtab += n.encode()
                else:
                    strtab += n.encode() + b'\x00'
                needed_entries.append((1, s_off))  # DT_NEEDED = 1
            else:
                needed_entries.append((1, n))

    dyn_entries = [
        (DT_HASH, 0x2080),
        (DT_STRTAB, 0x2200),
    ]
    if not omit_strsz:
        strsz_val = custom_strsz if custom_strsz is not None else len(strtab)
        dyn_entries.append((DT_STRSZ, strsz_val))

    dyn_entries.extend([
        (DT_SYMTAB, 0x2400),
        (DT_SYMENT, 24),
    ])
    dyn_entries.extend(needed_entries)

    if relas:
        dyn_entries.extend([
            (DT_RELA, 0x2600),
            (DT_RELASZ, len(relas)),
            (DT_RELAENT, 24),
            (DT_PLTREL, 7),
        ])
    dyn_entries.append((DT_NULL, 0))
    dyn_bytes = b''.join(struct.pack('<qQ', tag, val) for tag, val in dyn_entries)

    data = bytearray(0x3000)
    ehdr = struct.pack(
        '<16sHHIQQQIHHHHHH',
        ELFMAG + bytes([ELFCLASS64, ELFDATA2LSB, EV_CURRENT, 0]) + b'\x00' * 8,
        ET_DYN, EM_AARCH64, 1, 0, 64, 0, 0, 64, 56, 3, 64, 0, 0
    )
    data[:len(ehdr)] = ehdr

    ph_code = struct.pack('<IIQQQQQQ', PT_LOAD, PF_R | PF_X, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000, 0x1000)
    ph_data = struct.pack('<IIQQQQQQ', PT_LOAD, PF_R | PF_W, 0x2000, 0x2000, 0x2000, 0x1000, 0x1000, 0x1000)
    ph_dyn = struct.pack('<IIQQQQQQ', PT_DYNAMIC, PF_R | PF_W, 0x2000, 0x2000, 0x2000, len(dyn_bytes), len(dyn_bytes), 8)

    data[64:64 + 56] = ph_code
    data[64 + 56:64 + 112] = ph_data
    data[64 + 112:64 + 168] = ph_dyn

    data[0x2000:0x2000 + len(dyn_bytes)] = dyn_bytes
    data[0x2080:0x2080 + len(hash_bytes)] = hash_bytes
    data[0x2200:0x2200 + len(strtab)] = strtab
    data[0x2400:0x2400 + len(symtab)] = symtab
    if relas:
        data[0x2600:0x2600 + len(relas)] = relas

    return bytes(data)


class TestE05ElfLoaderDryRun(unittest.TestCase):
    """End-to-end dry-run tests using the 4 Durak 25.0 target binaries."""

    @classmethod
    def setUpClass(cls):
        for p in [SQLITE3_PATH, MAIN_PATH, UNITY_PATH, IL2CPP_PATH]:
            if not os.path.exists(p):
                raise unittest.SkipTest(f"Target binary missing: {p}")

        cls.loader = MultiModuleLoader(0x7000000000)
        cls.mod_sqlite3 = cls.loader.load_module(SQLITE3_PATH)
        cls.mod_main = cls.loader.load_module(MAIN_PATH)
        cls.mod_unity = cls.loader.load_module(UNITY_PATH)
        cls.mod_il2cpp = cls.loader.load_module(IL2CPP_PATH)
        cls.loader.relocate_all(strict=False)
        cls.wx_results = cls.loader.finalize_wx()

    def test_01_load_all_four_modules_layout_and_64k_alignment(self):
        """Verify strict 64 KiB alignment on libsqlite3.so and valid non-overlapping layout."""
        # 1. libsqlite3.so max_align must be 64 KiB (0x10000)
        self.assertEqual(self.mod_sqlite3.max_align, 0x10000, "libsqlite3.so must require 64 KiB alignment")
        self.assertEqual(self.mod_sqlite3.base_addr % 0x10000, 0, "libsqlite3.so base must align to 64 KiB")

        # 2. Others require 16 KiB (0x4000)
        for mod in [self.mod_main, self.mod_unity, self.mod_il2cpp]:
            self.assertEqual(mod.max_align, 0x4000)
            self.assertEqual(mod.base_addr % 0x4000, 0)

        # 3. Virtual address spans must be strictly non-overlapping
        mods = [self.mod_sqlite3, self.mod_main, self.mod_unity, self.mod_il2cpp]
        for i in range(len(mods) - 1):
            curr_end = mods[i].base_addr + mods[i].load_size
            next_start = mods[i + 1].base_addr
            self.assertLessEqual(
                curr_end, next_start,
                f"{mods[i].name} [{mods[i].base_addr:#x}..{curr_end:#x}) overlaps with {mods[i+1].name} @ {next_start:#x}"
            )

        # 4. Check expected segment counts
        self.assertEqual(len(self.mod_sqlite3.load_segments), 2)
        self.assertEqual(len(self.mod_main.load_segments), 4)
        self.assertEqual(len(self.mod_unity.load_segments), 4)
        self.assertEqual(len(self.mod_il2cpp.load_segments), 4)

    def test_02_bss_zero_initialization(self):
        """Verify BSS regions (where p_memsz > p_filesz) are initialized to zero."""
        for mod in [self.mod_sqlite3, self.mod_main, self.mod_unity, self.mod_il2cpp]:
            for seg in mod.load_segments:
                if seg.p_memsz > seg.p_filesz:
                    bss_start = (seg.p_vaddr - mod.min_vaddr) + seg.p_filesz
                    bss_size = seg.p_memsz - seg.p_filesz
                    bss_bytes = mod.memory[bss_start:bss_start + bss_size]
                    self.assertEqual(
                        set(bss_bytes), {0},
                        f"{mod.name} segment [{seg.p_vaddr:#x}] BSS contains non-zero bytes"
                    )

    def test_03_relocations_classification_and_init_array(self):
        """Verify dynamic relocations classification and .init_array pointer population."""
        # sqlite3 relocations
        sqlite3_types = {r.r_type for r in self.mod_sqlite3.relocations}
        self.assertIn(R_AARCH64_RELATIVE, sqlite3_types)
        self.assertIn(R_AARCH64_ABS64, sqlite3_types)
        self.assertIn(R_AARCH64_GLOB_DAT, sqlite3_types)
        self.assertIn(R_AARCH64_JUMP_SLOT, sqlite3_types)

        # libunity .init_array: 506 functions, on disk they are 0, in memory they must be resolved
        self.assertEqual(len(self.mod_unity.init_array), 506)
        # On disk, init_array entries are 0:
        init_arr_va = self.mod_unity.dynamic_tags.get(25)  # DT_INIT_ARRAY
        disk_off = self.mod_unity.vaddr_to_file_offset(init_arr_va)
        disk_val = struct.unpack('<Q', self.mod_unity.raw_data[disk_off:disk_off + 8])[0]
        self.assertEqual(disk_val, 0, "libunity.so .init_array first entry on disk should be 0 before relocation")

        # In memory, it must have been relocated to within libunity address space
        mem_val = self.mod_unity.read_memory_u64(init_arr_va)
        self.assertGreater(mem_val, self.mod_unity.base_addr)
        self.assertLess(mem_val, self.mod_unity.base_addr + self.mod_unity.load_size)

    def test_04_weak_vs_strong_symbols_and_unresolved_inventory(self):
        """Verify weak symbols resolve to NULL/addend and strong unresolved symbols are tracked."""
        # Weak undefined symbols (e.g. pthread_create in sqlite3)
        self.assertGreaterEqual(len(self.loader.unresolved_weak), 1)
        weak_names = {x["symbol"] for x in self.loader.unresolved_weak}
        self.assertIn("pthread_create", weak_names)

        # Strong unresolved symbols: exactly 758 call sites across all 4 modules
        self.assertEqual(len(self.loader.unresolved_strong), 758)

        # Report categorizer checks
        rep = self.loader.generate_report()
        cat_counts = rep["summary"]["categorized_unresolved_strong"]
        for required_cat in ["libc_mem_string", "libc_pthread", "libc_stdio_fs", "libandroid", "libm", "libEGL", "libdl", "liblog", "libz"]:
            self.assertIn(required_cat, cat_counts, f"Category {required_cat} missing from report")
            self.assertGreater(cat_counts[required_cat], 0, f"Category {required_cat} has 0 unresolved symbols")

    def test_05_wx_memory_protection_compliance(self):
        """Verify strict W^X enforcement (zero W^X pages, RELRO write stripping)."""
        for res in self.wx_results:
            self.assertTrue(res["wx_compliant"], f"W^X violation in {res['module']}: {res['wx_violation_addresses']}")
            self.assertEqual(res["wx_violations_count"], 0)
            self.assertGreater(res["rx_pages"], 0, f"No RX pages in {res['module']}")
            self.assertGreater(res["rw_pages"], 0, f"No RW pages in {res['module']}")
            self.assertGreater(res["ro_pages"], 0, f"No RO pages in {res['module']}")

        # Ensure all 4 modules have PT_GNU_RELRO
        for mod in [self.mod_sqlite3, self.mod_main, self.mod_unity, self.mod_il2cpp]:
            self.assertIsNotNone(mod.relro_segment, f"{mod.name} missing PT_GNU_RELRO")

    def test_06_report_generation_json_and_markdown(self):
        """Verify JSON and Markdown report outputs contain correct keys and structure."""
        with tempfile.TemporaryDirectory() as td:
            json_path = os.path.join(td, "report.json")
            md_path = os.path.join(td, "report.md")

            rep = self.loader.generate_report()
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(rep, f)

            self.loader.write_markdown_report(md_path)

            self.assertTrue(os.path.exists(json_path))
            self.assertTrue(os.path.exists(md_path))
            self.assertGreater(os.path.getsize(json_path), 50000)
            self.assertGreater(os.path.getsize(md_path), 1000)

            with open(md_path, 'r', encoding='utf-8') as f:
                md_content = f.read()

            self.assertIn("Durak NX — Звіт", md_content)
            self.assertIn("E05 Host Model", md_content)
            self.assertIn("libsqlite3.so", md_content)
            self.assertIn("libunity.so", md_content)
            self.assertIn("libc (Memory/String)", md_content)
            self.assertIn("Порушень правила W^X:** `0`", md_content)
            self.assertIn("Загальний статус W^X:** `PASS (0 порушень)`", md_content)
            self.assertTrue(rep["summary"]["wx_overall_compliant"])
            self.assertEqual(rep["summary"]["total_wx_violations"], 0)
            self.assertIn("wx_results", rep)
            self.assertEqual(len(rep["wx_results"]), 4)


class TestE05SyntheticRelocationsAndLinker(unittest.TestCase):
    """Synthetic unit tests for multi-module symbol resolution, weak symbols, and strict mode."""

    def test_07_synthetic_cross_module_resolution_glob_dat(self):
        """Module A exports symbol in PT_LOAD; Module B imports via R_AARCH64_GLOB_DAT with load bias."""
        # Symbol defined at 0x1120 inside PT_LOAD [0x1000..0x2000]
        raw_a = build_dynamic_elf(exports=[("target_exported_symbol", 0x1120)])
        raw_b = build_dynamic_elf(imports=[("target_exported_symbol", R_AARCH64_GLOB_DAT, 0x2800, 0x40)])

        with tempfile.TemporaryDirectory() as td:
            pa = os.path.join(td, "liba.so")
            pb = os.path.join(td, "libb.so")
            with open(pa, 'wb') as f: f.write(raw_a)
            with open(pb, 'wb') as f: f.write(raw_b)

            loader = MultiModuleLoader(0x6000000000)
            ma = loader.load_module(pa)
            mb = loader.load_module(pb)
            loader.relocate_all(strict=True)

            val = mb.read_memory_u64(0x2800)
            # Correct ELF resolution uses load_bias (base_addr - min_vaddr):
            # ma.load_bias = 0x6000000000 - 0x1000 = 0x5ffffff000
            # resolved = 0x5ffffff000 + 0x1120 + 0x40 = 0x6000000160
            expected = ma.load_bias + 0x1120 + 0x40
            self.assertEqual(val, expected)
            self.assertEqual(val, ma.base_addr + 0x160)
            self.assertNotEqual(val, ma.base_addr + 0x1160, "Must not add raw vaddr to base_addr when min_vaddr != 0")
            self.assertEqual(len(loader.cross_resolved), 1)
            self.assertEqual(loader.cross_resolved[0]["symbol"], "target_exported_symbol")
            self.assertEqual(loader.cross_resolved[0]["provider"], "liba.so")
            self.assertEqual(loader.cross_resolved[0]["consumer"], "libb.so")

    def test_08_synthetic_cross_module_resolution_jump_slot(self):
        """Module A exports function in PT_LOAD; Module B PLT imports via R_AARCH64_JUMP_SLOT."""
        # Function defined at 0x1450 inside PT_LOAD [0x1000..0x2000]
        raw_a = build_dynamic_elf(exports=[("unity_main_entry", 0x1450)])
        raw_b = build_dynamic_elf(imports=[("unity_main_entry", R_AARCH64_JUMP_SLOT, 0x2900, 0x0)])

        with tempfile.TemporaryDirectory() as td:
            pa = os.path.join(td, "liba.so")
            pb = os.path.join(td, "libb.so")
            with open(pa, 'wb') as f: f.write(raw_a)
            with open(pb, 'wb') as f: f.write(raw_b)

            loader = MultiModuleLoader(0x6000000000)
            ma = loader.load_module(pa)
            mb = loader.load_module(pb)
            loader.relocate_all(strict=True)

            val = mb.read_memory_u64(0x2900)
            expected = ma.load_bias + 0x1450
            self.assertEqual(val, expected)
            self.assertEqual(val, ma.base_addr + 0x450)
            self.assertNotEqual(val, ma.base_addr + 0x1450)
            self.assertEqual(len(loader.cross_resolved), 1)

    def test_09_synthetic_weak_symbol_resolves_to_null_or_addend(self):
        """Undefined weak symbol resolves to addend (or NULL) without error."""
        raw_b = build_dynamic_elf(imports=[("optional_callback", R_AARCH64_GLOB_DAT, 0x2800, 0x8)], is_weak=True)

        with tempfile.TemporaryDirectory() as td:
            pb = os.path.join(td, "libb.so")
            with open(pb, 'wb') as f: f.write(raw_b)

            loader = MultiModuleLoader(0x6000000000)
            mb = loader.load_module(pb)
            loader.relocate_all(strict=False)

            val = mb.read_memory_u64(0x2800)
            self.assertEqual(val, 0x8, "Weak symbol must resolve to addend (0x8)")
            self.assertEqual(len(loader.unresolved_weak), 1)
            self.assertEqual(len(loader.unresolved_strong), 0)

    def test_10_strict_mode_raises_on_unresolved_strong_symbol(self):
        """relocate_all(strict=True) must raise UnresolvedSymbolError when strong symbol missing."""
        raw_b = build_dynamic_elf(imports=[("missing_libc_function", R_AARCH64_GLOB_DAT, 0x2800, 0)], is_weak=False)

        with tempfile.TemporaryDirectory() as td:
            pb = os.path.join(td, "libb.so")
            with open(pb, 'wb') as f: f.write(raw_b)

            loader = MultiModuleLoader(0x6000000000)
            loader.load_module(pb)
            with self.assertRaises(UnresolvedSymbolError) as ctx:
                loader.relocate_all(strict=True)
            self.assertIn("missing_libc_function", str(ctx.exception))


class TestE05ElfValidationNegative(unittest.TestCase):
    """Negative mutations and boundary checks (Fail-Closed)."""

    def _load_raw(self, raw_bytes: bytes, filename="test_mod.so"):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, filename)
            with open(p, 'wb') as f:
                f.write(raw_bytes)
            return ElfModule(p)

    def test_11_missing_file_raises(self):
        with self.assertRaises(ElfValidationError) as ctx:
            ElfModule("/non/existent/path/libfake.so")
        self.assertIn("File not found", str(ctx.exception))

    def test_12_truncated_file_raises(self):
        with self.assertRaises(ElfValidationError) as ctx:
            self._load_raw(b'\x7fELF' + b'\x00' * 20)
        self.assertIn("too small", str(ctx.exception))

    def test_13_corrupt_magic_raises(self):
        raw = build_synthetic_elf(e_ident=b'NOPE\x02\x01\x01\x00' + b'\x00' * 8)
        with self.assertRaises(ElfValidationError) as ctx:
            self._load_raw(raw)
        self.assertIn("Invalid ELF magic", str(ctx.exception))

    def test_14_invalid_elf_class_raises(self):
        raw = build_synthetic_elf(e_ident=ELFMAG + bytes([ELFCLASS32, ELFDATA2LSB, EV_CURRENT, 0]) + b'\x00' * 8)
        with self.assertRaises(ElfValidationError) as ctx:
            self._load_raw(raw)
        self.assertIn("Expected ELFCLASS64", str(ctx.exception))

    def test_15_invalid_endianness_raises(self):
        raw = build_synthetic_elf(e_ident=ELFMAG + bytes([ELFCLASS64, ELFDATA2MSB, EV_CURRENT, 0]) + b'\x00' * 8)
        with self.assertRaises(ElfValidationError) as ctx:
            self._load_raw(raw)
        self.assertIn("Expected little-endian", str(ctx.exception))

    def test_16_invalid_version_raises(self):
        raw = build_synthetic_elf(e_ident=ELFMAG + bytes([ELFCLASS64, ELFDATA2LSB, 99, 0]) + b'\x00' * 8)
        with self.assertRaises(ElfValidationError) as ctx:
            self._load_raw(raw)
        self.assertIn("Invalid ELF version", str(ctx.exception))

    def test_17_non_shared_object_type_raises(self):
        raw = build_synthetic_elf(e_type=ET_EXEC)
        with self.assertRaises(ElfValidationError) as ctx:
            self._load_raw(raw)
        self.assertIn("Expected ET_DYN", str(ctx.exception))

    def test_18_wrong_machine_architecture_raises(self):
        raw = build_synthetic_elf(e_machine=0x3E)  # EM_X86_64
        with self.assertRaises(ElfValidationError) as ctx:
            self._load_raw(raw)
        self.assertIn("Expected EM_AARCH64", str(ctx.exception))

    def test_19_invalid_phentsize_raises(self):
        raw = build_synthetic_elf(phentsize=48)
        with self.assertRaises(ElfValidationError) as ctx:
            self._load_raw(raw)
        self.assertIn("Unexpected Elf64_Phdr size", str(ctx.exception))

    def test_20_program_headers_extend_past_eof_raises(self):
        raw = build_synthetic_elf(phnum=10, total_file_size=100)
        with self.assertRaises(ElfValidationError) as ctx:
            self._load_raw(raw)
        self.assertIn("Program headers exceed file bounds", str(ctx.exception))

    def test_21_segment_filesz_exceeds_memsz_raises(self):
        raw = build_synthetic_elf(p_filesz=0x500, p_memsz=0x200)
        with self.assertRaises(ElfValidationError) as ctx:
            self._load_raw(raw)
        self.assertIn("p_filesz (0x500) > p_memsz (0x200)", str(ctx.exception))

    def test_22_segment_extends_past_eof_raises(self):
        raw = build_synthetic_elf(p_offset=0x1000, p_filesz=0x500, p_memsz=0x500, total_file_size=0x1200)
        with self.assertRaises(ElfValidationError) as ctx:
            self._load_raw(raw)
        self.assertIn("extends beyond EOF", str(ctx.exception))

    def test_23_misaligned_vaddr_and_offset_raises(self):
        # p_align=0x1000, but offset % 0x1000 != vaddr % 0x1000
        raw = build_synthetic_elf(p_vaddr=0x1000, p_offset=0x1020, p_align=0x1000)
        with self.assertRaises(ElfValidationError) as ctx:
            self._load_raw(raw)
        self.assertIn("misaligned", str(ctx.exception))

    def test_24_overlapping_pt_load_segments_raises(self):
        # Segment 0: vaddr 0x1000..0x3000; Segment 1: vaddr 0x2000..0x3000 (overlaps!)
        seg1 = (PT_LOAD, PF_R | PF_W, 0x2000, 0x2000, 0x2000, 0x1000, 0x1000, 0x1000)
        raw = build_synthetic_elf(p_vaddr=0x1000, p_offset=0x1000, p_filesz=0x2000, p_memsz=0x2000, phnum=2, extra_segments=[seg1])
        with self.assertRaises(ElfValidationError) as ctx:
            self._load_raw(raw)
        self.assertIn("Overlapping PT_LOAD segments", str(ctx.exception))

    def test_25_no_pt_load_segments_raises(self):
        # ELF with phnum=1 but p_type is PT_NOTE, no PT_LOAD
        raw = build_synthetic_elf(p_offset=0x100, p_vaddr=0, p_filesz=0x20, p_memsz=0x20)
        data = bytearray(raw)
        # overwrite p_type at offset 64 to PT_NOTE
        data[64:68] = struct.pack('<I', PT_NOTE)
        with self.assertRaises(ElfValidationError) as ctx:
            self._load_raw(bytes(data))
        self.assertIn("No PT_LOAD segments found", str(ctx.exception))

    def test_26_unaligned_base_address_raises(self):
        raw = build_synthetic_elf(p_align=0x10000)  # 64 KiB align
        mod = self._load_raw(raw)
        with self.assertRaises(ElfValidationError) as ctx:
            mod.map_into_memory(0x7000004000)  # Misaligned to 64 KiB!
        self.assertIn("not aligned to max_align", str(ctx.exception))

    def test_27_duplicate_module_in_loader_raises(self):
        raw = build_synthetic_elf()
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "libmod.so")
            with open(p, 'wb') as f: f.write(raw)

            loader = MultiModuleLoader()
            loader.load_module(p)
            with self.assertRaises(ElfValidationError) as ctx:
                loader.load_module(p)
            self.assertIn("already loaded", str(ctx.exception))

    def test_28_wx_violation_detected_when_segment_has_rwx(self):
        """Verify W^X enforcement catches segments with PF_W | PF_X."""
        raw = build_synthetic_elf(p_flags=PF_R | PF_W | PF_X)
        mod = self._load_raw(raw)
        mod.map_into_memory(0x7000000000)
        res = mod.enforce_wx_permissions()
        self.assertFalse(res["wx_compliant"])
        self.assertGreater(res["wx_violations_count"], 0)
        self.assertIn(0x7000000000, res["wx_violation_addresses"])

    def test_29_relocation_out_of_bounds_raises(self):
        raw = build_synthetic_elf()
        mod = self._load_raw(raw)
        mod.map_into_memory(0x7000000000)
        with self.assertRaises(ElfValidationError) as ctx:
            mod.write_reloc_value(0x99999999, 0x1234)
        self.assertTrue(
            "out of bounds" in str(ctx.exception) or "does not fall inside any mapped PT_LOAD" in str(ctx.exception)
        )

    def test_30_non_power_of_two_p_align_raises(self):
        """p_align must be power of 2; p_align=3 must be rejected (Finding 5)."""
        raw = build_synthetic_elf(p_align=3)
        with self.assertRaises(ElfValidationError) as ctx:
            self._load_raw(raw)
        self.assertIn("must be a power of 2", str(ctx.exception))

    def test_31_unmapped_dynamic_table_vaddr_raises(self):
        """Dynamic table VA pointing outside file-backed PT_LOAD must be rejected (Finding 3)."""
        raw = bytearray(build_dynamic_elf(exports=[("foo", 0x1120)]))
        # Corrupt DT_STRTAB (5) tag in PT_DYNAMIC at 0x2000 to point to unmapped 0x100
        for off in range(0x2000, 0x2080, 16):
            tag = struct.unpack('<q', raw[off:off + 8])[0]
            if tag == 5:  # DT_STRTAB
                raw[off + 8:off + 16] = struct.pack('<Q', 0x100)  # unmapped VA!
                break
        with self.assertRaises(ElfValidationError) as ctx:
            mod = self._load_raw(bytes(raw))
            mod.map_into_memory(0x6000000000)
        self.assertIn("not contained in any file-backed PT_LOAD", str(ctx.exception))

    def test_32_relocation_target_in_unmapped_gap_raises(self):
        """Relocation targeting unmapped hole between segments must be rejected (Finding 4)."""
        # Segment 0: 0x1000..0x1200; Segment 1: 0x2000..0x2200; gap: 0x1200..0x2000
        seg1 = (PT_LOAD, PF_R | PF_W, 0x2000, 0x2000, 0x2000, 0x200, 0x200, 0x1000)
        raw = build_synthetic_elf(p_vaddr=0x1000, p_offset=0x1000, p_filesz=0x200, p_memsz=0x200, phnum=2, extra_segments=[seg1])
        mod = self._load_raw(raw)
        mod.map_into_memory(0x6000000000)
        # Attempt to write relocation into gap at 0x1800
        with self.assertRaises(ElfValidationError) as ctx:
            mod.write_reloc_value(0x1800, 0x1234)
        self.assertIn("does not fall inside any mapped PT_LOAD segment", str(ctx.exception))

    def test_33_exact_dynsym_counts_verified(self):
        """Exact dynamic symbol counts from DT_HASH / DT_GNU_HASH match true tables without overruns (Finding 3)."""
        # libunity has exactly 350 dynamic symbols; libil2cpp has exactly 2694
        self.assertEqual(len(TestE05ElfLoaderDryRun.mod_unity.symbols), 350)
        self.assertEqual(len(TestE05ElfLoaderDryRun.mod_il2cpp.symbols), 2694)
        self.assertEqual(len(TestE05ElfLoaderDryRun.mod_sqlite3.symbols), 779)
        self.assertEqual(len(TestE05ElfLoaderDryRun.mod_main.symbols), 14)

    def test_34_load_bias_math_verification(self):
        """Verify load_bias = base_addr - min_vaddr across all modules (Finding 2)."""
        for mod in [TestE05ElfLoaderDryRun.mod_sqlite3, TestE05ElfLoaderDryRun.mod_main,
                    TestE05ElfLoaderDryRun.mod_unity, TestE05ElfLoaderDryRun.mod_il2cpp]:
            self.assertEqual(mod.load_bias, mod.base_addr - mod.min_vaddr)

    def test_35_shn_abs_cross_module_resolution_omits_load_bias(self):
        """Cross-module R_AARCH64_GLOB_DAT to SHN_ABS symbol must resolve to sym.value + addend without load_bias."""
        # Module A has min_vaddr = 0x1000, exports absolute symbol with value 0x4000
        raw_a = build_dynamic_elf(exports=[("abs_symbol", 0x4000, SHN_ABS)])
        # Module B imports it via GLOB_DAT at offset 0x2800 with addend 0x18
        raw_b = build_dynamic_elf(imports=[("abs_symbol", R_AARCH64_GLOB_DAT, 0x2800, 0x18)])

        with tempfile.TemporaryDirectory() as td:
            pa = os.path.join(td, "liba.so")
            pb = os.path.join(td, "libb.so")
            with open(pa, 'wb') as f: f.write(raw_a)
            with open(pb, 'wb') as f: f.write(raw_b)

            loader = MultiModuleLoader(0x6000000000)
            ma = loader.load_module(pa)
            mb = loader.load_module(pb)
            loader.relocate_all(strict=True)

            val = mb.read_memory_u64(0x2800)
            expected = 0x4000 + 0x18
            self.assertEqual(val, expected, f"SHN_ABS symbol resolution must be sym.value + addend ({expected:#x}), got {val:#x}")
            # Ensure load_bias was NOT added
            self.assertNotEqual(val, ma.load_bias + 0x4000 + 0x18)
            self.assertEqual(len(loader.cross_resolved), 1)
            self.assertEqual(loader.cross_resolved[0]["symbol"], "abs_symbol")

    def test_36_shn_abs_internal_resolution_omits_load_bias(self):
        """Internal relocation referencing a local SHN_ABS symbol must resolve without load_bias."""
        raw_a = build_dynamic_elf(
            exports=[("internal_abs_symbol", 0x5000, SHN_ABS)],
            imports=[("internal_abs_symbol", R_AARCH64_GLOB_DAT, 0x2800, 0x20)]
        )

        with tempfile.TemporaryDirectory() as td:
            pa = os.path.join(td, "liba.so")
            with open(pa, 'wb') as f: f.write(raw_a)

            loader = MultiModuleLoader(0x6000000000)
            ma = loader.load_module(pa)
            loader.relocate_all(strict=True)

            val = ma.read_memory_u64(0x2800)
            expected = 0x5000 + 0x20
            self.assertEqual(val, expected, f"Internal SHN_ABS resolution must be sym.value + addend ({expected:#x}), got {val:#x}")
            self.assertNotEqual(val, ma.load_bias + 0x5000 + 0x20)

    def test_37_libsqlite3_exports_shn_abs_symbols(self):
        """Verify Durak's libsqlite3.so correctly indexes SHN_ABS symbols."""
        sqlite_syms = TestE05ElfLoaderDryRun.mod_sqlite3.exported_symbols
        expected_abs = ["_bss_end__", "__bss_start", "__end__", "__bss_start__", "_edata", "__bss_end__", "_end"]
        for sym_name in expected_abs:
            self.assertIn(sym_name, sqlite_syms, f"libsqlite3.so must export {sym_name}")
            sym = sqlite_syms[sym_name]
            self.assertTrue(sym.is_absolute, f"{sym_name} must have is_absolute == True")
            self.assertEqual(sym.shndx, SHN_ABS, f"{sym_name} shndx must be SHN_ABS")

    def test_38_missing_or_nonpositive_dt_strsz_raises(self):
        """Dynamic table with missing or non-positive DT_STRSZ must be rejected (Finding 3)."""
        raw_missing = build_dynamic_elf(exports=[("sym", 0x1100)], omit_strsz=True)
        with self.assertRaises(ElfValidationError) as ctx:
            mod = self._load_raw(raw_missing)
            mod.map_into_memory(0x6000000000)
        self.assertIn("Missing or non-positive DT_STRSZ", str(ctx.exception))

        raw_zero = build_dynamic_elf(exports=[("sym", 0x1100)], custom_strsz=0)
        with self.assertRaises(ElfValidationError) as ctx:
            mod = self._load_raw(raw_zero)
            mod.map_into_memory(0x6000000000)
        self.assertIn("Missing or non-positive DT_STRSZ", str(ctx.exception))

    def test_39_dt_needed_bounds_and_null_termination(self):
        """DT_NEEDED string index >= DT_STRSZ or missing null terminator must be rejected (Finding 3)."""
        # DT_NEEDED index 0x500 exceeds DT_STRSZ (~0x20)
        raw_oob = build_dynamic_elf(exports=[("sym", 0x1100)], dt_needed=[0x500])
        with self.assertRaises(ElfValidationError) as ctx:
            mod = self._load_raw(raw_oob)
            mod.map_into_memory(0x6000000000)
        self.assertIn("DT_NEEDED string index", str(ctx.exception))

        # Unterminated DT_NEEDED string within DT_STRSZ
        raw_unterminated = build_dynamic_elf(exports=[("sym", 0x1100)], dt_needed=["libmissing_nul.so"], corrupt_needed_strtab_nul=True)
        with self.assertRaises(ElfValidationError) as ctx:
            mod = self._load_raw(raw_unterminated)
            mod.map_into_memory(0x6000000000)
        self.assertIn("Unterminated DT_NEEDED string", str(ctx.exception))

    def test_40_symbol_name_bounds_and_null_termination(self):
        """Symbol st_name >= DT_STRSZ or unterminated name must be rejected (Finding 3)."""
        # Set DT_STRSZ smaller than symbol name offset
        raw_small_strsz = build_dynamic_elf(exports=[("very_long_symbol_name", 0x1100)], custom_strsz=1)
        with self.assertRaises(ElfValidationError) as ctx:
            mod = self._load_raw(raw_small_strsz)
            mod.map_into_memory(0x6000000000)
        self.assertIn("st_name", str(ctx.exception))
        self.assertIn(">= DT_STRSZ", str(ctx.exception))

        # Unterminated symbol name within DT_STRSZ
        raw_unterminated_sym = build_dynamic_elf(exports=[("unterminated_sym", 0x1100)], corrupt_symbol_strtab_nul=True)
        with self.assertRaises(ElfValidationError) as ctx:
            mod = self._load_raw(raw_unterminated_sym)
            mod.map_into_memory(0x6000000000)
        self.assertIn("not null-terminated within DT_STRSZ", str(ctx.exception))

    def test_41_cli_rwx_violation_fail_closed_exit_code_2(self):
        """CLI must fail closed with exit code 2 when any module has W^X violations (Finding 1)."""
        rwx_raw = build_synthetic_elf(p_flags=PF_R | PF_W | PF_X)
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "librwx.so")
            with open(p, 'wb') as f:
                f.write(rwx_raw)

            proc = subprocess.run(
                [sys.executable, os.path.join(TOOLS_DIR, "elf_loader.py"), "--modules", p],
                cwd=WORKSPACE_ROOT,
                capture_output=True,
                text=True
            )
            self.assertEqual(proc.returncode, 2, f"Expected exit code 2 on W^X violation, got {proc.returncode}")
            self.assertIn("W^X permission violation detected", proc.stderr + proc.stdout)

    def test_42_cli_default_mode_four_so_without_manifest_fails(self):
        """CLI default mode must fail closed with exit code 1 if all 4 .so exist but game_manifest.json is missing."""
        with tempfile.TemporaryDirectory() as td:
            ext_dir = os.path.join(td, "extracted_durak")
            os.makedirs(ext_dir, exist_ok=True)
            shutil.copyfile(SQLITE3_PATH, os.path.join(ext_dir, "libsqlite3.so"))
            shutil.copyfile(MAIN_PATH, os.path.join(ext_dir, "libmain.so"))
            shutil.copyfile(UNITY_PATH, os.path.join(ext_dir, "libunity.so"))
            shutil.copyfile(IL2CPP_PATH, os.path.join(ext_dir, "libil2cpp.so"))
            # Note: No game_manifest.json copied!

            proc = subprocess.run(
                [sys.executable, os.path.join(TOOLS_DIR, "elf_loader.py")],
                cwd=td,
                capture_output=True,
                text=True
            )
            self.assertEqual(proc.returncode, 1, f"Expected exit code 1 when manifest is missing, got {proc.returncode}")
            self.assertIn("Required game manifest not found in default mode", proc.stderr + proc.stdout)

    def test_43_cli_default_mode_forged_so_and_manifest_fails(self):
        """CLI default mode must fail closed with exit code 1 when .so and manifest are consistently forged."""
        with tempfile.TemporaryDirectory() as td:
            ext_dir = os.path.join(td, "extracted_durak")
            os.makedirs(ext_dir, exist_ok=True)

            fake_content = b"FORGED_ELF_CONTENT"
            fake_sha = hashlib.sha256(fake_content).hexdigest()
            for fn in ["libsqlite3.so", "libmain.so", "libunity.so", "libil2cpp.so"]:
                with open(os.path.join(ext_dir, fn), 'wb') as f:
                    f.write(fake_content)

            # Consistently forged manifest matching the fake .so files
            forged_manifest = {
                "package_info": {
                    "package_name": EXPECTED_PACKAGE,
                    "version_name": EXPECTED_VERSION_NAME,
                    "version_code": EXPECTED_VERSION_CODE,
                    "verified": True
                },
                "core_libraries": {
                    fn: {
                        "size": len(fake_content),
                        "sha256": fake_sha,
                        "verified": True
                    } for fn in ["libsqlite3.so", "libmain.so", "libunity.so", "libil2cpp.so"]
                }
            }
            with open(os.path.join(ext_dir, "game_manifest.json"), 'w', encoding='utf-8') as f:
                json.dump(forged_manifest, f)

            proc = subprocess.run(
                [sys.executable, os.path.join(TOOLS_DIR, "elf_loader.py")],
                cwd=td,
                capture_output=True,
                text=True
            )
            self.assertEqual(proc.returncode, 1, f"Expected exit code 1 on forged .so and manifest, got {proc.returncode}")
            self.assertTrue(
                "Manifest SHA-256 mismatch" in proc.stderr + proc.stdout or
                "Trusted SHA-256 mismatch" in proc.stderr + proc.stdout
            )

    def test_44_cli_default_mode_invalid_package_info_fails(self):
        """CLI default mode must fail closed with exit code 1 if package_name, version, or verified flag are invalid."""
        valid_manifest_path = os.path.join(DATA_DIR, "game_manifest.json")
        with open(valid_manifest_path, 'r', encoding='utf-8') as f:
            base_manifest = json.load(f)

        test_cases = [
            ({"package_name": "com.fake.durak"}, "package_name mismatch"),
            ({"version_name": "24.0"}, "version_name mismatch"),
            ({"version_code": 240}, "version_code mismatch"),
            ({"verified": False}, "package_info.verified is not True"),
        ]

        for patch_dict, expected_err in test_cases:
            with tempfile.TemporaryDirectory() as td:
                ext_dir = os.path.join(td, "extracted_durak")
                os.makedirs(ext_dir, exist_ok=True)
                shutil.copyfile(SQLITE3_PATH, os.path.join(ext_dir, "libsqlite3.so"))
                shutil.copyfile(MAIN_PATH, os.path.join(ext_dir, "libmain.so"))
                shutil.copyfile(UNITY_PATH, os.path.join(ext_dir, "libunity.so"))
                shutil.copyfile(IL2CPP_PATH, os.path.join(ext_dir, "libil2cpp.so"))

                mutated_manifest = json.loads(json.dumps(base_manifest))
                mutated_manifest["package_info"].update(patch_dict)
                with open(os.path.join(ext_dir, "game_manifest.json"), 'w', encoding='utf-8') as f:
                    json.dump(mutated_manifest, f)

                proc = subprocess.run(
                    [sys.executable, os.path.join(TOOLS_DIR, "elf_loader.py")],
                    cwd=td,
                    capture_output=True,
                    text=True
                )
                self.assertEqual(proc.returncode, 1, f"Expected exit code 1 for mutation {patch_dict}, got {proc.returncode}")
                self.assertIn(expected_err, proc.stderr + proc.stdout)

    def test_45_cli_default_mode_missing_core_library_from_disk_fails(self):
        """CLI default mode must fail closed with exit code 1 if a core library is missing from disk."""
        valid_manifest_path = os.path.join(DATA_DIR, "game_manifest.json")
        with tempfile.TemporaryDirectory() as td:
            ext_dir = os.path.join(td, "extracted_durak")
            os.makedirs(ext_dir, exist_ok=True)
            shutil.copyfile(SQLITE3_PATH, os.path.join(ext_dir, "libsqlite3.so"))
            shutil.copyfile(MAIN_PATH, os.path.join(ext_dir, "libmain.so"))
            shutil.copyfile(UNITY_PATH, os.path.join(ext_dir, "libunity.so"))
            # libil2cpp.so is omitted!
            shutil.copyfile(valid_manifest_path, os.path.join(ext_dir, "game_manifest.json"))

            proc = subprocess.run(
                [sys.executable, os.path.join(TOOLS_DIR, "elf_loader.py")],
                cwd=td,
                capture_output=True,
                text=True
            )
            self.assertEqual(proc.returncode, 1, f"Expected exit code 1 for missing libil2cpp.so, got {proc.returncode}")
            self.assertIn("Missing core Durak 25.0 library", proc.stderr + proc.stdout)

    def test_46_verify_durak_default_environment_api_success(self):
        """Verify the direct verify_durak_default_environment API against the authentic DATA_DIR."""
        verified_mods = verify_durak_default_environment(DATA_DIR)
        self.assertEqual(len(verified_mods), 4)
        for p in verified_mods:
            self.assertTrue(os.path.isfile(p))

    def test_47_e05_4b_android_shims_resolution_reduction(self):
        """Verify that Wave 3 Android shim registry (149 symbols) reduces unresolved strong relocations by exactly 271 sites (758 -> 487)."""
        loader = MultiModuleLoader(0x7000000000)
        mods = [SQLITE3_PATH, MAIN_PATH, UNITY_PATH, IL2CPP_PATH]
        for m in mods:
            loader.load_module(m)

        loader.relocate_all(strict=False, external_resolver=resolve_android_shim)

        # Baseline was 758 strong sites, 4 weak sites, 0 cross.
        # With Wave 3 shims: 149 symbols registered, 271 relocation sites resolved!
        self.assertEqual(len(ANDROID_SHIM_SYMBOLS), 149)
        self.assertEqual(len(loader.external_resolved), 271)
        self.assertEqual(len(loader.unresolved_strong), 487)
        self.assertEqual(len(loader.unresolved_weak), 4)
        self.assertEqual(len(loader.cross_resolved), 0)

        # Verify that no remaining strong unresolved symbol is present in ANDROID_SHIM_SYMBOLS
        remaining_symbols = {item["symbol"] for item in loader.unresolved_strong}
        overlap = remaining_symbols.intersection(ANDROID_SHIM_SYMBOLS)
        self.assertEqual(len(overlap), 0, f"Overlap between remaining and shims: {overlap}")

    def test_48_external_resolver_called_exactly_once_per_relocation(self):
        """Verify that external_resolver is called exactly once per relocation site (no duplicate calls)."""
        loader = MultiModuleLoader(0x7000000000)
        mods = [SQLITE3_PATH, MAIN_PATH, UNITY_PATH, IL2CPP_PATH]
        for m in mods:
            loader.load_module(m)

        call_log = []

        def tracking_resolver(sym_name: str):
            call_log.append(sym_name)
            return resolve_android_shim(sym_name)

        loader.relocate_all(strict=False, external_resolver=tracking_resolver)

        # Total relocation sites evaluated by external_resolver:
        # 271 resolved + 487 unresolved strong + 4 unresolved weak = 762 calls total.
        self.assertEqual(len(loader.external_resolved), 271)
        self.assertEqual(len(loader.unresolved_strong), 487)
        self.assertEqual(len(loader.unresolved_weak), 4)
        self.assertEqual(len(call_log), 271 + 487 + 4)

    # Old-backend C registry parity test is archived with that backend.
    # This suite tests tools/elf_loader.py; active C runtime uses the native harness.

    def test_50_subprocess_deterministic_reports_across_hash_seeds(self):
        """Verify that reports generated with different PYTHONHASHSEED are byte-for-byte identical."""
        elf_loader_script = os.path.join(TOOLS_DIR, "elf_loader.py")
        self.assertTrue(os.path.isfile(elf_loader_script))

        seeds = ["0", "42", "1337", "random"]
        reports_json = []
        reports_md = []

        with tempfile.TemporaryDirectory() as tmpdir:
            for seed in seeds:
                json_path = os.path.join(tmpdir, f"report_{seed}.json")
                md_path = os.path.join(tmpdir, f"report_{seed}.md")

                env = os.environ.copy()
                env["PYTHONHASHSEED"] = seed

                cmd = [
                    sys.executable,
                    elf_loader_script,
                    "--shims",
                    "--report-json", json_path,
                    "--report-md", md_path,
                ]

                proc = subprocess.run(
                    cmd,
                    cwd=WORKSPACE_ROOT,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(proc.returncode, 0, f"elf_loader.py failed under seed {seed}:\n{proc.stderr}")

                with open(json_path, "rb") as f:
                    reports_json.append((seed, f.read()))
                with open(md_path, "rb") as f:
                    reports_md.append((seed, f.read()))

        # Verify byte-for-byte identity of JSON across all seeds
        base_seed, base_json = reports_json[0]
        for seed, jdata in reports_json[1:]:
            self.assertEqual(
                base_json,
                jdata,
                f"Nondeterminism in JSON report between PYTHONHASHSEED={base_seed} and {seed}!"
            )

        # Verify byte-for-byte identity of Markdown across all seeds
        base_seed, base_md = reports_md[0]
        for seed, mdata in reports_md[1:]:
            self.assertEqual(
                base_md,
                mdata,
                f"Nondeterminism in Markdown report between PYTHONHASHSEED={base_seed} and {seed}!"
            )

    def test_51_baseline_report_without_shims(self):
        """Verify baseline report semantics when shims are not enabled (addressing Codex LOW finding)."""
        loader = MultiModuleLoader(0x7000000000)
        mods = [SQLITE3_PATH, MAIN_PATH, UNITY_PATH, IL2CPP_PATH]
        for m in mods:
            loader.load_module(m)

        # Baseline: do not provide external_resolver
        loader.relocate_all(strict=False, external_resolver=None)

        self.assertFalse(loader.shims_enabled)
        self.assertEqual(len(loader.external_resolved), 0)
        self.assertEqual(len(loader.unresolved_strong), 758)
        self.assertEqual(len(loader.unresolved_weak), 4)

        report = loader.generate_report()
        s = report["summary"]
        self.assertFalse(s["shims_enabled"])
        self.assertEqual(s["available_shim_symbols_count"], 149)
        self.assertEqual(s["registered_shim_symbols_count"], 0)
        self.assertEqual(s["external_resolved_count"], 0)
        self.assertEqual(s["unresolved_strong_count"], 758)
        self.assertEqual(s["unresolved_weak_count"], 4)

        with tempfile.TemporaryDirectory() as tmpdir:
            md_path = os.path.join(tmpdir, "baseline.md")
            loader.write_markdown_report(md_path)
            with open(md_path, "r", encoding="utf-8") as f:
                md_text = f.read()

            self.assertIn("- **Зареєстровано зовнішніх shim-символів (E05.4b):** 0 (вимкнено, доступно в реєстрі: 149)", md_text)
            self.assertIn("- **Зовнішніх shim-релокацій розв'язано (relocation sites):** 0", md_text)
            self.assertIn("- **Незв'язаних strong (GLOBAL) релокацій (relocation sites):** 758", md_text)


if __name__ == "__main__":
    unittest.main()
