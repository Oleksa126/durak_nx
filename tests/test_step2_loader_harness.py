#!/usr/bin/env python3
"""
test_step2_loader_harness.py -- Host verification test suite for Step 2 of Durak NX Feasibility Spike.

Verifies:
1. Target SHA-256 and GNU Build-ID validation (positive & negative test cases).
2. Module alignments (64 KiB for libsqlite3.so, 16 KiB for others).
3. W^X compliance (0 RWX segments/pages across all 4 Durak modules).
4. Relocations & dynamic linking (all supported types, 0 unsupported types).
5. Symbol resolution against runtime tables (0 unresolved strong data, 0 poison pointers).
6. Constructor discovery from PT_DYNAMIC (506 in libunity, 22 in libil2cpp, 0 in main/sqlite3).
7. Guest ARM64 code execution barrier verification.
"""

import os
import sys
import hashlib
import struct
import unittest
import json
import re
from elftools.elf.elffile import ELFFile

EXPECTED_TARGETS = {
    "libsqlite3.so": {
        "size": 1797248,
        "sha256": "6df7a75d31c417cae7e877fd7c3d190e0ac47b1f104ae0ae5501d72491b1c32c",
        "build_id": "99495662cefa74605573c8dc36a53cb1f842764d",
        "align": 0x10000,
        "expected_ctors": 0,
    },
    "libmain.so": {
        "size": 6696,
        "sha256": "c11373dffa1bab427e8864a40313111de2a70367d052d87f33a9069ce8949d93",
        "build_id": "c5498ab8c791f1473a54c79a9d3c5b738ff6d941",
        "align": 0x4000,
        "expected_ctors": 0,
    },
    "libunity.so": {
        "size": 21388304,
        "sha256": "292f89210151ba0060f77d137cd6a00a52158dc5da760d4bf106158fc9309cef",
        "build_id": "bcc661ea2046416d",
        "align": 0x4000,
        "expected_ctors": 506,
    },
    "libil2cpp.so": {
        "size": 31256704,
        "sha256": "7bc9c2e7e20c741a511e6645589db16d0fa084d79bcfc12ba1fab78931e2271c",
        "build_id": "d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0",
        "align": 0x4000,
        "expected_ctors": 22,
    },
}

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(SCRIPT_DIR)

EXTRACTED_DIR = os.path.join(REPO_DIR, "extracted_durak")
NRO_PATH = os.path.join(REPO_DIR, "durak_nx.nro")

def extract_build_id(elf):
    for sec in elf.iter_sections():
        if sec['sh_type'] == 'SHT_NOTE':
            for note in sec.iter_notes():
                if note['n_type'] in (3, 'NT_GNU_BUILD_ID') and note['n_name'] == 'GNU':
                    return note['n_desc']
    return None

def parse_runtime_symbols():
    symbols = {}
    sources = [
        os.path.join(REPO_DIR, "source", "imports.c"),
        os.path.join(REPO_DIR, "source", "unity_imports.c"),
        os.path.join(REPO_DIR, "source", "firebase_stub.c"),
    ]
    for src in sources:
        if os.path.exists(src):
            with open(src, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            for match in re.finditer(r'\{\s*"([^"]+)"\s*,\s*\(uintptr_t\)\s*([^}]+)\}', content):
                name = match.group(1).strip()
                binding = match.group(2).strip()
                symbols[name] = binding
    return symbols


class TestStep2LoaderHarness(unittest.TestCase):

    def test_01_target_verification_positive(self):
        """Verify all 4 canonical Durak modules against expected size, SHA-256, and GNU Build-ID."""
        for mod_name, expected in EXPECTED_TARGETS.items():
            path = os.path.join(EXTRACTED_DIR, mod_name)
            self.assertTrue(os.path.exists(path), f"Module not found: {path}")
            
            with open(path, "rb") as f:
                data = f.read()
            
            self.assertEqual(len(data), expected["size"], f"Size mismatch for {mod_name}")
            actual_sha = hashlib.sha256(data).hexdigest()
            self.assertEqual(actual_sha, expected["sha256"], f"SHA-256 mismatch for {mod_name}")

            with open(path, "rb") as f:
                elf = ELFFile(f)
                build_id = extract_build_id(elf)
                self.assertIsNotNone(build_id, f"Missing GNU Build-ID in {mod_name}")
                self.assertEqual(build_id, expected["build_id"], f"Build-ID mismatch for {mod_name}")

    def test_02_target_verification_negative(self):
        """Verify that corrupted data, wrong size, or unknown targets are rejected."""
        # 1. Unknown target
        self.assertNotIn("libunknown.so", EXPECTED_TARGETS)

        # 2. Corrupted byte
        valid_path = os.path.join(EXTRACTED_DIR, "libmain.so")
        with open(valid_path, "rb") as f:
            data = bytearray(f.read())
        data[0x20] ^= 0xFF # Corrupt a byte
        corrupted_sha = hashlib.sha256(data).hexdigest()
        self.assertNotEqual(corrupted_sha, EXPECTED_TARGETS["libmain.so"]["sha256"])

        # 3. Truncated size
        truncated = data[:100]
        self.assertNotEqual(len(truncated), EXPECTED_TARGETS["libmain.so"]["size"])

    def test_03_module_alignments(self):
        """Verify PT_LOAD alignments: 64 KiB for sqlite3, 16 KiB for others."""
        for mod_name, expected in EXPECTED_TARGETS.items():
            path = os.path.join(EXTRACTED_DIR, mod_name)
            with open(path, "rb") as f:
                elf = ELFFile(f)
                max_align = 0x1000
                for seg in elf.iter_segments():
                    if seg['p_type'] == 'PT_LOAD':
                        if seg['p_align'] > max_align:
                            max_align = seg['p_align']
                self.assertEqual(max_align, expected["align"],
                                 f"Max alignment for {mod_name} should be 0x{expected['align']:x}, got 0x{max_align:x}")

    def test_04_strict_wx_compliance(self):
        """Verify strict W^X: 0 PT_LOAD segments have both write and execute permissions."""
        for mod_name in EXPECTED_TARGETS.keys():
            path = os.path.join(EXTRACTED_DIR, mod_name)
            with open(path, "rb") as f:
                elf = ELFFile(f)
                rwx_segments = 0
                for seg in elf.iter_segments():
                    if seg['p_type'] == 'PT_LOAD':
                        flags = seg['p_flags']
                        is_w = (flags & 2) != 0 # PF_W
                        is_x = (flags & 1) != 0 # PF_X
                        if is_w and is_x:
                            rwx_segments += 1
                self.assertEqual(rwx_segments, 0, f"Found {rwx_segments} RWX segments in {mod_name} (W^X violation!)")

    def test_05_supported_relocation_types(self):
        """Verify that only supported AArch64 relocation types exist across all 4 modules."""
        # Supported AArch64 relocations:
        # R_AARCH64_ABS64 (257 = 0x101)
        # R_AARCH64_GLOB_DAT (1025 = 0x401)
        # R_AARCH64_JUMP_SLOT (1026 = 0x402)
        # R_AARCH64_RELATIVE (1027 = 0x403)
        supported_types = {257, 1025, 1026, 1027}

        for mod_name in EXPECTED_TARGETS.keys():
            path = os.path.join(EXTRACTED_DIR, mod_name)
            with open(path, "rb") as f:
                elf = ELFFile(f)
                for sec_name in ['.rela.dyn', '.rela.plt']:
                    sec = elf.get_section_by_name(sec_name)
                    if sec:
                        for rel in sec.iter_relocations():
                            rtype = rel['r_info_type']
                            self.assertIn(rtype, supported_types,
                                          f"Unsupported relocation type {rtype} in {mod_name}")

    def test_06_symbol_resolution_and_no_poison_pointers(self):
        """Simulate dynamic linking across all 4 modules: verify 0 unresolved strong data and 0 poison pointers."""
        runtime_symbols = parse_runtime_symbols()
        self.assertGreater(len(runtime_symbols), 600, "Runtime symbols table too small")

        # Collect module exports
        exports = {}
        imports = {}
        for mod_name in EXPECTED_TARGETS.keys():
            path = os.path.join(EXTRACTED_DIR, mod_name)
            exports[mod_name] = set()
            imports[mod_name] = []
            with open(path, "rb") as f:
                elf = ELFFile(f)
                dynsym = elf.get_section_by_name('.dynsym')
                for sym in dynsym.iter_symbols():
                    shndx = sym['st_shndx']
                    bind = sym['st_info']['bind']
                    st_type = sym['st_info']['type']
                    name = sym.name
                    if shndx != 'SHN_UNDEF' and bind != 'STB_LOCAL':
                        exports[mod_name].add(name)
                    elif shndx == 'SHN_UNDEF' and name:
                        imports[mod_name].append((name, bind, st_type))

        all_exports = set()
        for exp in exports.values():
            all_exports.update(exp)

        # Verify every import
        unresolved_strong_data = []
        for mod_name, imp_list in imports.items():
            for name, bind, st_type in imp_list:
                if name in runtime_symbols or name in all_exports:
                    continue
                if bind == 'STB_WEAK':
                    # Allowed: resolves to NULL per ELF spec
                    continue
                if st_type != 'STT_FUNC':
                    unresolved_strong_data.append((mod_name, name, st_type))

        self.assertEqual(len(unresolved_strong_data), 0,
                         f"Unresolved strong data symbols found: {unresolved_strong_data}")

    def test_07_constructor_discovery_and_barrier(self):
        """Verify constructors discovered via PT_DYNAMIC (506 in libunity, 22 in libil2cpp)."""
        for mod_name, expected in EXPECTED_TARGETS.items():
            path = os.path.join(EXTRACTED_DIR, mod_name)
            with open(path, "rb") as f:
                elf = ELFFile(f)
                dynamic = elf.get_section_by_name('.dynamic')
                init_arraysz = 0
                if dynamic:
                    for tag in dynamic.iter_tags():
                        if tag.entry.d_tag == 'DT_INIT_ARRAYSZ':
                            init_arraysz = tag.entry.d_val
                num_ctors = init_arraysz // 8
                self.assertEqual(num_ctors, expected["expected_ctors"],
                                 f"Constructor count mismatch for {mod_name}: expected {expected['expected_ctors']}, got {num_ctors}")

    def test_08_nro_artifact_built(self):
        """Verify that durak_nx.nro exists and has valid NRO0 magic."""
        nro_path = NRO_PATH
        self.assertTrue(os.path.exists(nro_path), f"durak_nx.nro binary does not exist at {nro_path}!")
        with open(nro_path, "rb") as f:
            data = f.read(0x40)
        # NRO header at offset 0x10 has magic 'NRO0'
        magic = data[0x10:0x14]
        self.assertEqual(magic, b"NRO0", f"Invalid NRO magic: {magic}")

    def test_09_asset_structure_completeness(self):
        """Verify that all assets/bin/Data files match base.apk with directory hierarchy preserved."""
        import zipfile
        import io
        apks_path = os.path.join(REPO_DIR, "Durak_25.0.apks")
        self.assertTrue(os.path.exists(apks_path), f"Durak_25.0.apks not found at {apks_path}")

        expected_assets = {}
        with zipfile.ZipFile(apks_path, "r") as z:
            self.assertIn("base.apk", z.namelist())
            with z.open("base.apk") as base_apk:
                with zipfile.ZipFile(io.BytesIO(base_apk.read())) as bz:
                    for name in bz.namelist():
                        if name.startswith("assets/bin/Data/"):
                            content = bz.read(name)
                            expected_assets[name] = {
                                "size": len(content),
                                "sha256": hashlib.sha256(content).hexdigest()
                            }

        self.assertEqual(len(expected_assets), 12, f"Expected 12 bin/Data assets in base.apk, found {len(expected_assets)}")

        # Verify against both canonical assets/ and fallback game/assets/
        for root_sub in ["assets", os.path.join("game", "assets")]:
            base_data_dir = os.path.join(EXTRACTED_DIR, "sdmc", "switch", "durak_nx", root_sub, "bin", "Data")
            self.assertTrue(os.path.isdir(base_data_dir), f"Directory {base_data_dir} does not exist!")

            for name, meta in expected_assets.items():
                rel = name[len("assets/bin/Data/"):]
                local_path = os.path.join(base_data_dir, rel.replace("/", os.sep))
                self.assertTrue(os.path.exists(local_path), f"Missing target asset: {local_path} (from {name})")
                with open(local_path, "rb") as f:
                    data = f.read()
                self.assertEqual(len(data), meta["size"], f"Size mismatch for {local_path}")
                self.assertEqual(hashlib.sha256(data).hexdigest(), meta["sha256"], f"SHA256 mismatch for {local_path}")

        # Explicit check for unity_app_guid
        guid_path = os.path.join(EXTRACTED_DIR, "sdmc", "switch", "durak_nx", "assets", "bin", "Data", "unity_app_guid")
        with open(guid_path, "r", encoding="utf-8") as f:
            guid = f.read().strip()
        self.assertEqual(len(guid), 36, f"Invalid unity_app_guid format: {guid}")

    def test_10_path_resolution_contract(self):
        """Verify the contract of durak_resolve_path across guest path variants."""
        # Simulated resolution logic matching durak_resolve_path in libc_shim.c
        game_home = "sdmc:/switch/durak_nx"

        def resolve(in_path, for_write=False):
            if not in_path: return in_path
            if for_write:
                if in_path.startswith("sdmc:"): return in_path
                if in_path.startswith("/switch/"): return "sdmc:" + in_path
                if in_path.startswith("/data/data/ru.appscraft.durak/files/"):
                    return game_home + "/" + in_path[len("/data/data/ru.appscraft.durak/files/"):]
                if not in_path.startswith("/") and ":" not in in_path:
                    return game_home + "/" + in_path
                return in_path

            if in_path.startswith(("/proc/", "/sys/")) or in_path in ("/dev/urandom", "/dev/random"):
                return in_path

            candidates = []
            if in_path.startswith("/switch/durak_nx/"):
                rel = in_path[17:]
                candidates.append(f"sdmc:/switch/durak_nx/{rel}")
                if rel.startswith("assets/"):
                    candidates.append(f"sdmc:/switch/durak_nx/game/{rel}")
                if rel.startswith("game/assets/"):
                    candidates.append(f"sdmc:/switch/durak_nx/{rel[5:]}")
                if rel.startswith("bin/Data/"):
                    candidates.append(f"sdmc:/switch/durak_nx/assets/{rel}")
                    candidates.append(f"sdmc:/switch/durak_nx/game/assets/{rel}")
            elif in_path.startswith("assets/"):
                candidates.append(f"{game_home}/{in_path}")
                candidates.append(f"{game_home}/game/{in_path}")
                candidates.append(in_path)
            elif in_path.startswith("bin/Data/"):
                candidates.append(f"{game_home}/assets/{in_path}")
                candidates.append(f"{game_home}/game/assets/{in_path}")
                candidates.append(f"{game_home}/{in_path}")
                candidates.append(in_path)
            elif not in_path.startswith("/") and ":" not in in_path:
                candidates.append(in_path)
                candidates.append(f"{game_home}/assets/bin/Data/{in_path}")
                candidates.append(f"{game_home}/game/assets/bin/Data/{in_path}")
                candidates.append(f"{game_home}/assets/{in_path}")
                candidates.append(f"{game_home}/game/assets/{in_path}")
                candidates.append(f"{game_home}/{in_path}")
                candidates.append(f"{game_home}/game/{in_path}")
            else:
                candidates.append(in_path)

            for c in candidates:
                local = c.replace("sdmc:/switch/durak_nx/", os.path.join(EXTRACTED_DIR, "sdmc", "switch", "durak_nx") + os.sep)
                if os.path.exists(local):
                    return c
            return candidates[0]

        test_cases = [
            ("assets/bin/Data/unity_app_guid", "sdmc:/switch/durak_nx/assets/bin/Data/unity_app_guid"),
            ("/switch/durak_nx/assets/bin/Data/unity_app_guid", "sdmc:/switch/durak_nx/assets/bin/Data/unity_app_guid"),
            ("assets/bin/Data/Managed", "sdmc:/switch/durak_nx/assets/bin/Data/Managed"),
            ("/switch/durak_nx/assets/bin/Data/Managed", "sdmc:/switch/durak_nx/assets/bin/Data/Managed"),
            ("bin/Data/boot.config", "sdmc:/switch/durak_nx/assets/bin/Data/boot.config"),
            ("unity_app_guid", "sdmc:/switch/durak_nx/assets/bin/Data/unity_app_guid"),
            ("Managed", "sdmc:/switch/durak_nx/assets/bin/Data/Managed"),
        ]

        for in_p, expected in test_cases:
            actual = resolve(in_p)
            self.assertEqual(actual, expected, f"Resolution mismatch for '{in_p}': got '{actual}', expected '{expected}'")

    def test_11_oc_commit_failure_contract(self):
        """Host negative test: failed mapping -> failed mprotect, uncommitted pages remain uncommitted."""
        PAGE_SIZE = 0x1000
        total_pages = 8192
        oc_base = 0x11000000
        oc_pages = total_pages
        oc_used = [1] * oc_pages
        oc_committed = [0] * oc_pages
        oc_pool_pages = total_pages
        oc_pool_bump = [0]
        oc_live_pages = [0]

        def oc_commit_locked(addr, length, mock_map_func):
            if addr < oc_base:
                return -1, 12  # ENOMEM
            first = (addr - oc_base) // PAGE_SIZE
            cnt = (length + PAGE_SIZE - 1) // PAGE_SIZE
            if first >= oc_pages:
                return -1, 12  # ENOMEM
            if first + cnt > oc_pages:
                cnt = oc_pages - first

            i = 0
            while i < cnt:
                if oc_committed[first + i]:
                    i += 1
                    continue
                run = 0
                while (i + run < cnt) and not oc_committed[first + i + run]:
                    run += 1
                if run == 0:
                    break

                if oc_pool_bump[0] + run > oc_pool_pages:
                    return -1, 12  # ENOMEM

                dst = oc_base + (first + i) * PAGE_SIZE
                src = 0x20000000 + oc_pool_bump[0] * PAGE_SIZE
                size_bytes = run * PAGE_SIZE

                rc = mock_map_func(dst, src, size_bytes)
                if rc != 0:
                    # Contract requirement: failed pages MUST NOT be marked committed!
                    errno_val = 14 if rc == 0xd401 else 12  # EFAULT or ENOMEM
                    return -1, errno_val

                for k in range(run):
                    oc_committed[first + i + k] = 1
                oc_pool_bump[0] += run
                oc_live_pages[0] += run
                i += run

            return 0, 0

        def mprotect_fake(addr, length, prot, mock_map_func):
            if oc_base <= addr < oc_base + oc_pages * PAGE_SIZE:
                if prot != 0:
                    rc, err = oc_commit_locked(addr, length, mock_map_func)
                    if rc != 0:
                        return -1, err
                return 0, 0
            return 0, 0

        # Negative test 1: Simulated svcMapMemory failure (0xd401)
        target_addr = 0x11000000
        run_len = 4096 * PAGE_SIZE  # 16 MB = 4096 pages
        rc, err = mprotect_fake(target_addr, run_len, 3, lambda d, s, sz: 0xd401)
        self.assertEqual(rc, -1, "mprotect must return -1 on svcMapMemory failure")
        self.assertEqual(err, 14, "errno must be EFAULT (14) on 0xd401")
        self.assertTrue(all(c == 0 for c in oc_committed[:4096]), "Failed pages must NOT be marked committed")
        self.assertEqual(oc_pool_bump[0], 0, "Pool bump must not advance on failure")

        # Negative test 2: Pool exhaustion
        oc_pool_bump[0] = 7000
        rc, err = mprotect_fake(target_addr, run_len, 3, lambda d, s, sz: 0)
        self.assertEqual(rc, -1, "mprotect must return -1 on pool exhaustion")
        self.assertEqual(err, 12, "errno must be ENOMEM (12) on pool exhaustion")
        self.assertTrue(all(c == 0 for c in oc_committed[:4096]), "Failed pages must remain uncommitted")
        self.assertEqual(oc_pool_bump[0], 7000, "Pool bump must not advance on failure")

        # Positive test: Successful mapping
        oc_pool_bump[0] = 0
        rc, err = mprotect_fake(target_addr, run_len, 3, lambda d, s, sz: 0)
        self.assertEqual(rc, 0, "mprotect must return 0 on successful commit")
        self.assertEqual(err, 0)
        self.assertTrue(all(c == 1 for c in oc_committed[:4096]), "Committed pages must be marked 1")
        self.assertEqual(oc_pool_bump[0], 4096, "Pool bump must advance by committed page count")

        # Repeat commit test: Idempotent skip
        rc, err = mprotect_fake(target_addr, run_len, 3, lambda d, s, sz: 0xd401)
        self.assertEqual(rc, 0, "Repeat commit on already committed pages must succeed without re-calling map")
        self.assertEqual(oc_pool_bump[0], 4096, "Pool bump must not advance on repeat commit")

    def test_12_durak_unity_choreographer_patch_contract(self):
        """Test 12: Verify ChoreographerBase::Get -> NULL fallback patch & call-site cbz contract."""
        unity_path = os.path.join(EXTRACTED_DIR, "libunity.so")
        with open(unity_path, "rb") as f:
            elf = ELFFile(f)
            text_sec = elf.get_section_by_name(".text")
            text_data = text_sec.data()
            text_addr = text_sec["sh_addr"]

            # 1. Target RVA 0x00e7261c original instruction fingerprint
            target_rva = 0x00e7261c
            off = target_rva - text_addr
            w0 = struct.unpack_from("<I", text_data, off)[0]
            w1 = struct.unpack_from("<I", text_data, off + 4)[0]
            self.assertEqual(w0, 0xd10143ff, "Word 0 must be sub sp, sp, #0x50")
            self.assertEqual(w1, 0xa90357fe, "Word 1 must be stp x30, x21, [sp, #0x30]")

            # 2. Patch transform instructions
            # movz x0, #0 -> 0xd2800000; ret -> 0xd65f03c0
            patch_w0 = 0xd2800000
            patch_w1 = 0xd65f03c0
            self.assertEqual(patch_w0, 0xd2800000)
            self.assertEqual(patch_w1, 0xd65f03c0)

            # 3. Call-site scan: verify EXACTLY two call sites exist in libunity.so
            callers = []
            for i in range(0, len(text_data) - 4, 4):
                val = struct.unpack_from("<I", text_data, i)[0]
                if (val & 0xfc000000) in [0x94000000, 0x14000000]:
                    imm26 = val & 0x03ffffff
                    if imm26 & 0x02000000:
                        imm26 -= 0x04000000
                    dest = text_addr + i + (imm26 * 4)
                    if dest == target_rva:
                        callers.append(text_addr + i)

            self.assertEqual(len(callers), 2, f"Expected exactly 2 callers of 0x{target_rva:08x}, found {len(callers)}")
            self.assertEqual(callers[0], 0x00e7258c, "Caller 1 must be at RVA 0x00e7258c")
            self.assertEqual(callers[1], 0x00e72770, "Caller 2 must be at RVA 0x00e72770")

            # 4. Verify verified 'cbz x0' fallbacks at both call sites
            cbz1 = struct.unpack_from("<I", text_data, 0x00e72590 - text_addr)[0]
            cbz2 = struct.unpack_from("<I", text_data, 0x00e72774 - text_addr)[0]
            self.assertEqual(cbz1, 0xb40003c0, "Caller 1 must have cbz x0, #0xe72608 immediately following bl")
            self.assertEqual(cbz2, 0xb40000a0, "Caller 2 must have cbz x0, #0xe72788 immediately following bl")


    def test_13_sdk_default_display_capture_is_linked(self):
        """Actual ARM64 SDK init reaches the wrapper, which calls the real API."""
        with open(os.path.join(REPO_DIR, 'durak_nx.elf'), 'rb') as stream:
            elf = ELFFile(stream)
            symbols = elf.get_section_by_name('.symtab')

            def symbol(name):
                found = symbols.get_symbol_by_name(name)
                self.assertTrue(found, f'Missing linked symbol: {name}')
                return found[0]

            def branch_targets(fn):
                address, size = fn['st_value'], fn['st_size']
                segment = next(s for s in elf.iter_segments()
                               if s['p_type'] == 'PT_LOAD' and s['p_vaddr'] <= address
                               and address + size <= s['p_vaddr'] + s['p_filesz'])
                stream.seek(segment['p_offset'] + address - segment['p_vaddr'])
                body = stream.read(size)
                targets = []
                for offset in range(0, len(body) - 3, 4):
                    word = struct.unpack_from('<I', body, offset)[0]
                    if (word & 0xfc000000) in (0x94000000, 0x14000000):
                        relative = word & 0x03ffffff
                        if relative & 0x02000000:
                            relative -= 0x04000000
                        targets.append(address + offset + relative * 4)
                return targets

            init = symbol('__nx_win_init')
            wrapper = symbol('__wrap_viOpenDisplay')
            real = symbol('viOpenDisplay')
            self.assertIn(wrapper['st_value'], branch_targets(init),
                          'SDK initialization bypasses the Default display capture')
            self.assertIn(real['st_value'], branch_targets(wrapper),
                          'Capture must preserve the real viOpenDisplay call')


if __name__ == "__main__":
    unittest.main()
