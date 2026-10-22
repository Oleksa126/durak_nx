#!/usr/bin/env python3
"""
durak_analyzer.py - Fail-Closed RVA & Patch Point Analyzer for Durak NX (ru.appscraft.durak)

Milestone M1 Implementation (E02 + E03 + E04):
  - Strict Target Manifest verification (APKS, split APKs, ELF build-ids, SHA-256)
  - Structural RegisterNatives discovery via ELF RELA relocations
  - Windowless Allocator Region Patch Scanner across ALL .text via multi-instruction fingerprints
  - Structural IL2CPP JNI Globals recovery from JNI_OnLoad disassembly
  - IL2CPP Metadata v39 parser with overloads disambiguation (GetInt1/2, GetString1/2)
  - ABI Analysis for value-type returns (UnityEngine.Touch, x8) and icall bindings
  - TimeManager::Update full basic block & relocation verification
  - Fail-closed: on any mismatch, aborts with non-zero exit code and removes target headers
"""

import sys
import os
import io
import json
import struct
import itertools
import argparse
from typing import Dict, List, Tuple, Optional, Any

from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

# Import sibling tools
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from extract_game import sha256_bytes, sha256_file, get_elf_build_id
from metadata_v39 import Il2CppMetadataV39, Il2CppMethodResolver

# ------------------------------------------------------------------------------
# Verified Target Expected Constants (Durak 25.0, Unity 6000.4.0b6)
# ------------------------------------------------------------------------------
EXPECTED_PACKAGE = "ru.appscraft.durak"
EXPECTED_VERSION_NAME = "25.0"
EXPECTED_VERSION_CODE = 250

EXPECTED_CORE_LIBRARIES = {
    "libmain.so": {
        "size": 6696,
        "sha256": "c11373dffa1bab427e8864a40313111de2a70367d052d87f33a9069ce8949d93",
        "build_id": "c5498ab8c791f1473a54c79a9d3c5b738ff6d941"
    },
    "libunity.so": {
        "size": 21388304,
        "sha256": "292f89210151ba0060f77d137cd6a00a52158dc5da760d4bf106158fc9309cef",
        "build_id": "bcc661ea2046416d"
    },
    "libil2cpp.so": {
        "size": 31256704,
        "sha256": "7bc9c2e7e20c741a511e6645589db16d0fa084d79bcfc12ba1fab78931e2271c",
        "build_id": "d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0"
    },
    "libsqlite3.so": {
        "size": 1797248,
        "sha256": "6df7a75d31c417cae7e877fd7c3d190e0ac47b1f104ae0ae5501d72491b1c32c",
        "build_id": "99495662cefa74605573c8dc36a53cb1f842764d"
    }
}

EXPECTED_METADATA_SIZE = 7639464
EXPECTED_METADATA_SHA256 = "1e31859eca996941dbdeb3ab9df208f4359422440110607494e74cc8cafc5b6a"

# The 18 original 256MB instruction words for VirtualAllocator / MemoryManager
ALLOCATOR_ORIG_WORDS = [
    0x12be0009, 0x92648d35, 0x52a20008, 0x52a20009, 0x52a20009, 0x12be000d,
    0x92648d36, 0xd35cdc33, 0xd35cfd15, 0x52a20008, 0xd35cfc28, 0x92646c28,
    0xd35c9c2a, 0xd35cdc29, 0xb25c6feb, 0xf2a2000b, 0xcb0a7108, 0xd35c9c29
]

ALLOCATOR_PATCH_WORDS = [
    0x12bf8009, 0x92669535, 0x52a08008, 0x52a08009, 0x52a08009, 0x12bf800d,
    0x92669536, 0xd35ad433, 0xd35afd15, 0x52a08008, 0xd35afc28, 0x92667428,
    0xd35a942a, 0xd35ad429, 0xb25e77eb, 0xf2a0800b, 0xcb0a6908, 0xd35a9429
]

ALLOCATOR_DESCRIPTIONS = [
    "MOV LocalLowLevelAllocator::ReserveMemoryBlock (256MB-1 mask hi)",
    "LOGIMM LocalLowLevelAllocator::ReserveMemoryBlock (~low28 mask)",
    "MOV TLSAllocator::ThreadInitialize (256MB const)",
    "MOV BucketAllocator::ctor (256MB const)",
    "MOV DynamicHeapAllocator::ctor (256MB region size)",
    "MOV DynamicHeapAllocator::RequestLargeAllocMemory (256MB-1 mask hi)",
    "LOGIMM DynamicHeapAllocator::RequestLargeAllocMemory (~low28 mask)",
    "BITF VirtualAllocator::MarkMemoryBlocks (ubfx #28,#28)",
    "BITF VirtualAllocator::MarkMemoryBlocks (lsr #28)",
    "MOV VirtualAllocator::ReserveMemoryBlock (256MB const)",
    "BITF VirtualAllocator::GetMemoryBlockFromPointer (lsr #28)",
    "LOGIMM VirtualAllocator::GetMemoryBlockFromPointer (~low28 mask)",
    "BITF VirtualAllocator::GetMemoryBlockFromPointer (ubfx #28,#12)",
    "BITF VirtualAllocator::GetMemoryBlockFromPointer (ubfx #28,#28)",
    "LOGIMM VirtualAllocator::GetMemoryBlockFromPointer (-255*gran hi)",
    "MOV VirtualAllocator::GetMemoryBlockFromPointer (movk 256MB)",
    "SHREG VirtualAllocator::GetMemoryBlockFromPointer (sub lsl #28)",
    "BITF VirtualAllocator::GetBlockInfoFromPointer (ubfx #28,#12)",
]

# Strict 3-instruction structural fingerprints (prev, target, next) for each allocator site
ALLOCATOR_FINGERPRINTS = [
    (0xf9400260, 0x12be0009, 0x7940126a),  # Site 1
    (0xf9400008, 0x92648d35, 0x92402942),  # Site 2
    (0xa9044ff4, 0x52a20008, 0x52800409),  # Site 3
    (0xb9805e68, 0x52a20009, 0xf9144274),  # Site 4
    (0xf9000269, 0x52a20009, 0x6f00e400),  # Site 5
    (0xa94f2260, 0x12be000d, 0x52a00802),  # Site 6
    (0x8b0b0129, 0x92648d36, 0x79409269),  # Site 7
    (0x9240dc28, 0xd35cdc33, 0x8b020108),  # Site 8
    (0x8b020108, 0xd35cfd15, 0x6b15027f),  # Site 9
    (0x8a090115, 0x52a20008, 0xad0183e0),  # Site 10
    (0xd65f03c0, 0xd35cfc28, 0x530c6d08),  # Site 11 (preceded by ret)
    (0xf9403109, 0x92646c28, 0xb4000389),  # Site 12
    (0xb4000389, 0xd35c9c2a, 0xb86a7929),  # Site 13
    (0x54000241, 0xd35cdc29, 0xb25c6feb),  # Site 14
    (0xd35cdc29, 0xb25c6feb, 0xf2a2000b),  # Site 15
    (0xb25c6feb, 0xf2a2000b, 0x5103fd2c),  # Site 16
    (0x7200293f, 0xcb0a7108, 0x9a8803e0),  # Site 17
    (0xb4000088, 0xd35c9c29, 0xb8697900)   # Site 18
]


class DurakFailClosedAnalyzer:
    def __init__(self, data_dir: str, test_mode: bool = False):
        self.data_dir = data_dir
        self.test_mode = test_mode
        self.integrity_verified = False
        self.unity_so = os.path.join(data_dir, "libunity.so")
        self.il2cpp_so = os.path.join(data_dir, "libil2cpp.so")
        self.metadata_dat = os.path.join(data_dir, "global-metadata.dat")
        self.manifest_json = os.path.join(data_dir, "game_manifest.json")

        self.cs_md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.cs_md.detail = True
        self.results: Dict[str, Any] = {
            "analyzer": "Durak NX Fail-Closed Analyzer",
            "milestone": "M1 (Verified target and evidence)",
            "target": "ru.appscraft.durak 25.0",
            "status": "IN_PROGRESS",
            "integrity_verified": False,
            "findings": {},
            "errors": []
        }

    def fail(self, msg: str):
        print(f"[!] FATAL ERROR: {msg}", file=sys.stderr)
        self.results["errors"].append(msg)
        self.results["status"] = "FAILED"
        self.results["integrity_verified"] = False
        raise RuntimeError(msg)

    # --------------------------------------------------------------------------
    # Helper: read VA from ELF
    # --------------------------------------------------------------------------
    @staticmethod
    def _get_load_segments(elf: ELFFile):
        return [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']

    @classmethod
    def _va_to_file_offset(cls, loads, va: int) -> Optional[int]:
        for s in loads:
            if s['p_vaddr'] <= va < s['p_vaddr'] + s['p_filesz']:
                return s['p_offset'] + (va - s['p_vaddr'])
        return None

    @classmethod
    def _get_segment_flags(cls, loads, va: int) -> str:
        for s in loads:
            if s['p_vaddr'] <= va < s['p_vaddr'] + s['p_memsz']:
                fl = s['p_flags']
                r = 'r' if (fl & 4) else '-'
                w = 'w' if (fl & 2) else '-'
                x = 'x' if (fl & 1) else '-'
                return f"{r}{w}{x}"
        return "---"

    @classmethod
    def _read_va(cls, f, loads, va: int, length: int) -> bytes:
        for s in loads:
            if s['p_vaddr'] <= va < s['p_vaddr'] + s['p_filesz']:
                avail = min(length, (s['p_vaddr'] + s['p_filesz']) - va)
                f.seek(s['p_offset'] + (va - s['p_vaddr']))
                return f.read(avail)
        return b''

    @classmethod
    def _read_cstr(cls, f, loads, va: int, max_len: int = 256) -> Optional[str]:
        raw = cls._read_va(f, loads, va, max_len)
        z = raw.find(b'\0')
        if z < 0: return None
        try:
            s = raw[:z].decode('utf-8')
            return s if all(32 <= ord(c) < 127 for c in s) else None
        except Exception:
            return None

    # --------------------------------------------------------------------------
    # 1. Target Manifest & Binary Identity Verification (FAIL-CLOSED)
    # --------------------------------------------------------------------------
    def verify_target_identities(self) -> Dict[str, Any]:
        print("[*] Verifying target binaries, build-ids, and integrity (Fail-Closed)...")

        # 1. Verify game_manifest.json if present
        if os.path.isfile(self.manifest_json):
            with open(self.manifest_json, 'r', encoding='utf-8') as f:
                manifest_data = json.load(f)

            pkg = manifest_data.get("package_info", {})
            if pkg.get("package_name") != EXPECTED_PACKAGE:
                self.fail(f"Manifest package mismatch: {pkg.get('package_name')} != {EXPECTED_PACKAGE}")
            if pkg.get("version_name") != EXPECTED_VERSION_NAME:
                self.fail(f"Manifest versionName mismatch: {pkg.get('version_name')} != {EXPECTED_VERSION_NAME}")
            if pkg.get("version_code") != EXPECTED_VERSION_CODE:
                self.fail(f"Manifest versionCode mismatch: {pkg.get('version_code')} != {EXPECTED_VERSION_CODE}")

            # Verify manifest core_libraries hashes
            m_libs = manifest_data.get("core_libraries", {})
            for fn, exp in EXPECTED_CORE_LIBRARIES.items():
                if fn not in m_libs:
                    self.fail(f"Manifest missing core library entry for: {fn}")
                if m_libs[fn].get("sha256") != exp["sha256"]:
                    self.fail(f"Manifest SHA-256 mismatch for {fn}: {m_libs[fn].get('sha256')} != {exp['sha256']}")
                if m_libs[fn].get("build_id") != exp["build_id"]:
                    self.fail(f"Manifest Build ID mismatch for {fn}: {m_libs[fn].get('build_id')} != {exp['build_id']}")

        # 2. Directly verify ELF files in data_dir
        verified_binaries = {}
        all_shas_matched = True
        for fn, exp in EXPECTED_CORE_LIBRARIES.items():
            fpath = os.path.join(self.data_dir, fn)
            if not os.path.isfile(fpath):
                self.fail(f"Required binary missing: {fpath}")

            with open(fpath, 'rb') as f:
                data = f.read()

            sz = len(data)
            h = sha256_bytes(data)
            actual_bid = get_elf_build_id(data)

            if sz != exp["size"]:
                self.fail(f"Size mismatch for {fn}: have {sz}, expected {exp['size']}")
            if h != exp["sha256"]:
                all_shas_matched = False
                if not self.test_mode:
                    self.fail(f"SHA-256 mismatch for {fn}: have {h}, expected {exp['sha256']}")
            if actual_bid != exp["build_id"]:
                self.fail(f"Build ID mismatch for {fn}: have {actual_bid}, expected {exp['build_id']}")

            # Directly parse ELF header
            try:
                elf = ELFFile(io.BytesIO(data))
                e_ident = elf.header['e_ident']
                elf_class = e_ident['EI_CLASS']
                elf_data = e_ident['EI_DATA']
                machine = elf.header['e_machine']

                if elf_class != 'ELFCLASS64':
                    self.fail(f"Invalid ELF class for {fn}: {elf_class} (expected ELFCLASS64)")
                if elf_data != 'ELFDATA2LSB':
                    self.fail(f"Invalid ELF endianness for {fn}: {elf_data} (expected ELFDATA2LSB)")
                if machine != 'EM_AARCH64':
                    self.fail(f"Invalid ELF machine architecture for {fn}: {machine} (expected EM_AARCH64)")
            except Exception as e:
                self.fail(f"Failed to parse ELF header of {fn}: {e}")

            verified_binaries[fn] = {
                "size": sz,
                "sha256": h,
                "build_id": actual_bid,
                "elf_class": elf_class,
                "machine": machine,
                "verified": True
            }
            print(f"    -> Verified {fn:<15} build-id={actual_bid} sha256={h[:16]}... [OK]")

        # 3. Verify global-metadata.dat
        if not os.path.isfile(self.metadata_dat):
            self.fail(f"global-metadata.dat missing at: {self.metadata_dat}")

        with open(self.metadata_dat, 'rb') as f:
            meta_bytes = f.read()

        m_sz = len(meta_bytes)
        m_sha = sha256_bytes(meta_bytes)
        if m_sz != EXPECTED_METADATA_SIZE:
            self.fail(f"global-metadata.dat size mismatch: have {m_sz}, expected {EXPECTED_METADATA_SIZE}")
        if m_sha != EXPECTED_METADATA_SHA256:
            all_shas_matched = False
            if not self.test_mode:
                self.fail(f"global-metadata.dat SHA-256 mismatch: have {m_sha}, expected {EXPECTED_METADATA_SHA256}")

        magic, ver = struct.unpack('<II', meta_bytes[:8])
        if magic != 0xFAB11BAF or ver != 39:
            self.fail(f"Invalid metadata magic ({hex(magic)}) or version ({ver})")

        self.integrity_verified = all_shas_matched and not self.test_mode

        meta_info = {
            "size": m_sz,
            "sha256": m_sha,
            "magic": hex(magic),
            "version": ver,
            "verified": True
        }
        print(f"    -> Verified global-metadata.dat size={m_sz} version={ver} [OK]")

        return {
            "binaries": verified_binaries,
            "metadata": meta_info,
            "status": "ALL_IDENTITIES_VERIFIED" if self.integrity_verified else "TEST_MODE_UNVERIFIED_INTEGRITY"
        }

    # --------------------------------------------------------------------------
    # 2. Structural RegisterNatives & Lifecycle Analyzer (libunity.so)
    # --------------------------------------------------------------------------
    def analyze_unity_natives(self) -> Dict[str, Any]:
        print("[*] Analyzing libunity.so RegisterNatives and exports...")
        res: Dict[str, Any] = {
            "tables": [],
            "lifecycle_entrypoints": {},
            "fmod_natives": {},
            "total_methods": 0
        }

        with open(self.unity_so, 'rb') as f:
            elf = ELFFile(f)
            loads = self._get_load_segments(elf)

            # Export check
            dynsym = elf.get_section_by_name('.dynsym')
            for sym in dynsym.iter_symbols():
                if sym.name in ('JNI_OnLoad', 'JNI_OnUnload'):
                    va = sym['st_value']
                    foff = self._va_to_file_offset(loads, va)
                    res["lifecycle_entrypoints"][sym.name] = {
                        "rva": hex(va),
                        "size": sym['st_size'],
                        "signature": "(JavaVM*, void*) -> jint" if sym.name == 'JNI_OnLoad' else "(JavaVM*, void*) -> void",
                        "confidence": "CONFIRMED_EXPORT",
                        "evidence": {
                            "virtual_address": hex(va),
                            "file_offset": hex(foff) if foff is not None else "0x0",
                            "segment_flags": self._get_segment_flags(loads, va),
                            "confidence_reason": f"Exported symbol {sym.name} in .dynsym"
                        }
                    }

            if "JNI_OnLoad" not in res["lifecycle_entrypoints"]:
                self.fail("JNI_OnLoad export missing from libunity.so")

            # Parse relocations to find RegisterNatives JNINativeMethod tables
            rela = elf.get_section_by_name('.rela.dyn')
            relocs = {}
            for r in rela.iter_relocations():
                if r['r_info_type'] == 1027:  # R_AARCH64_RELATIVE
                    relocs[r['r_offset']] = r['r_addend']

            def is_valid_jni_name(n: str) -> bool:
                if not n or not (n[0].isalpha() or n[0] == '_'): return False
                return all(c.isalnum() or c in '_$' for c in n)

            def is_valid_jni_sig(s: str) -> bool:
                if not s or not s.startswith('(') or ')' not in s: return False
                return True

            def is_va_executable(va: int) -> bool:
                for s in loads:
                    if (s['p_flags'] & 1) and (s['p_vaddr'] <= va < s['p_vaddr'] + s['p_memsz']):
                        return True
                return False

            text_sec = elf.get_section_by_name('.text')
            ro_sec = elf.get_section_by_name('.rodata')
            reg_sites = self._trace_registernatives_call_sites(elf, text_sec, ro_sec, relocs)
            res["call_sites"] = {
                hex(k): {
                    "registered_class": v["class_name"],
                    "call_site": hex(v["call_site"]),
                    "method_count": v["count"]
                }
                for k, v in sorted(reg_sites.items())
            }

            for idx, (table_vaddr, r_info) in enumerate(sorted(reg_sites.items())):
                table_class = r_info['class_name']
                table_cs = hex(r_info['call_site'])
                cnt = r_info['count']

                table_info = {
                    "table_id": idx + 1,
                    "table_vaddr": hex(table_vaddr),
                    "table_file_offset": hex(self._va_to_file_offset(loads, table_vaddr) or 0),
                    "method_count": cnt,
                    "registered_class": table_class,
                    "registration_call_site": table_cs,
                    "methods": []
                }

                for i in range(cnt):
                    m_va = table_vaddr + i * 24
                    name_va = relocs.get(m_va, 0)
                    sig_va = relocs.get(m_va + 8, 0)
                    fn_va = relocs.get(m_va + 16, 0)

                    name = self._read_cstr(f, loads, name_va)
                    sig = self._read_cstr(f, loads, sig_va)

                    if not name or not sig:
                        self.fail(f"Invalid or missing name/sig in table {hex(table_vaddr)} entry {i}")
                    if not is_valid_jni_name(name):
                        self.fail(f"Invalid JNI method name '{name}' in table {hex(table_vaddr)} entry {i}")
                    if not is_valid_jni_sig(sig):
                        self.fail(f"Invalid JNI signature '{sig}' for method '{name}' in table {hex(table_vaddr)}")
                    if not is_va_executable(fn_va):
                        self.fail(f"Non-executable function pointer {hex(fn_va)} for method '{name}' in table {hex(table_vaddr)}")
                    if not table_class or table_class == "Unknown":
                        self.fail(f"Fail-closed: Method '{name}' has unverified or Unknown class attribution")

                    foff = self._va_to_file_offset(loads, fn_va)
                    method_entry = {
                        "name": name,
                        "signature": sig,
                        "rva": hex(fn_va),
                        "slot_vaddr": hex(m_va),
                        "registered_class": table_class,
                        "registration_call_site": table_cs,
                        "evidence": {
                            "virtual_address": hex(fn_va),
                            "file_offset": hex(foff) if foff is not None else "0x0",
                            "slot_vaddr": hex(m_va),
                            "segment_flags": self._get_segment_flags(loads, fn_va),
                            "registered_class": table_class,
                            "registration_call_site": table_cs,
                            "table_rva": hex(table_vaddr),
                            "table_count": cnt,
                            "confidence_reason": f"Class '{table_class}' registered at call-site {table_cs} in table {hex(table_vaddr)}"
                        }
                    }
                    table_info["methods"].append(method_entry)

                    if table_class == 'org/fmod/FMODAudioDevice' or "fmod" in name.lower():
                        res["fmod_natives"][name] = {
                            "rva": hex(fn_va),
                            "signature": sig,
                            "table_id": idx + 1,
                            "registered_class": table_class,
                            "registration_call_site": table_cs,
                            "confidence": "CONFIRMED_STRUCTURAL",
                            "evidence": method_entry["evidence"]
                        }
                    else:
                        res["lifecycle_entrypoints"][name] = {
                            "rva": hex(fn_va),
                            "signature": sig,
                            "table_id": idx + 1,
                            "registered_class": table_class,
                            "registration_call_site": table_cs,
                            "confidence": "CONFIRMED_STRUCTURAL",
                            "evidence": method_entry["evidence"]
                        }

                res["tables"].append(table_info)

            res["total_methods"] = sum(t["method_count"] for t in res["tables"])
            if len(res["tables"]) != 14 or res["total_methods"] != 71:
                self.fail(f"Expected exactly 14 RegisterNatives tables with 71 methods, found {len(res['tables'])} tables with {res['total_methods']} methods")

        print(f"    -> Found {len(res['tables'])} tables, {res['total_methods']} native methods across {len(reg_sites)} call sites (100% confirmed)")
        return res

    def _trace_registernatives_call_sites(self, elf: ELFFile, text_sec, ro_sec, rels: Dict[int, int]) -> Dict[int, Dict[str, Any]]:
        """Trace all RegisterNatives call sites across .text structurally (0 hardcoded RVAs)."""
        code = text_sec.data()
        text_addr = text_sec['sh_addr']
        ro_data = ro_sec.data()
        ro_addr = ro_sec['sh_addr']

        def read_str(va: int) -> str:
            if ro_addr <= va < ro_addr + len(ro_data):
                pos = va - ro_addr
                end = ro_data.find(b'\0', pos)
                return ro_data[pos:end].decode('latin1', errors='replace')
            return ''

        # Structural scan of .text for JNIEnv->RegisterNatives (ldr reg, [reg, #0x6b8])
        # ARM64: 64-bit LDR unsigned immediate: (w >> 22) == 0x3e5 and imm12 == 215 (0x6b8)
        candidates = []
        for off in range(0, len(code), 4):
            w = struct.unpack('<I', code[off:off+4])[0]
            if (w >> 22) == 0x3e5:
                imm12 = (w >> 10) & 0xfff
                if imm12 == 215:
                    rn = (w >> 5) & 0x1f
                    rt = w & 0x1f
                    candidates.append((off, off + text_addr, rt, rn))

        reg_sites: Dict[int, Dict[str, Any]] = {}
        for off, va, rt, rn in candidates:
            w_start = max(0, off - 300)
            w_end = min(len(code), off + 32)
            insns = list(self.cs_md.disasm(code[w_start:w_end], text_addr + w_start))

            ldr_idx = next((i for i, ins in enumerate(insns) if ins.address == va), None)
            if ldr_idx is None:
                continue

            # Check for blr x{rt} within next 4 instructions
            blr_ins = None
            for j in range(ldr_idx + 1, min(ldr_idx + 5, len(insns))):
                if insns[j].mnemonic == 'blr' and insns[j].op_str == f'x{rt}':
                    blr_ins = insns[j]
                    break
            if not blr_ins:
                continue

            call_site = blr_ins.address
            count = None
            table_rva = None
            class_name = None

            prior = insns[max(0, ldr_idx - 70):ldr_idx]

            # Extract count (w3)
            for ins in reversed(prior):
                if ins.mnemonic == 'mov' and ins.op_str.startswith('w3, #'):
                    count = int(ins.op_str.split('#')[1], 0)
                    break

            if not count or count <= 0:
                continue

            # Extract table_rva (x2)
            for ins in reversed(prior):
                if ins.mnemonic == 'add' and ins.op_str.startswith('x2, x2, #'):
                    imm = int(ins.op_str.split('#')[1], 0)
                    p_idx = prior.index(ins)
                    for p2 in reversed(prior[:p_idx]):
                        if p2.mnemonic == 'adrp' and p2.op_str.startswith('x2, #'):
                            base = int(p2.op_str.split('#')[1], 0)
                            table_rva = base + imm
                            break
                    if table_rva:
                        break

            if not table_rva:
                continue

            # Extract class_name (x1)
            for ins in reversed(prior):
                if ins.mnemonic == 'add' and ins.op_str.startswith('x1, x1, #'):
                    imm = int(ins.op_str.split('#')[1], 0)
                    p_idx = prior.index(ins)
                    for p2 in reversed(prior[:p_idx]):
                        if p2.mnemonic == 'adrp' and p2.op_str.startswith('x1, #'):
                            base = int(p2.op_str.split('#')[1], 0)
                            st = read_str(base + imm)
                            if st:
                                class_name = st
                            break
                    if class_name:
                        break
                elif ins.mnemonic == 'mov' and ins.op_str.startswith('x1, x20'):
                    for ins2 in prior:
                        if ins2.mnemonic == 'ldr' and ins2.op_str.startswith('x20, [x22, #'):
                            imm = int(ins2.op_str.split('#')[1].rstrip(']'), 0)
                            p_idx = prior.index(ins2)
                            for p2 in reversed(prior[:p_idx]):
                                if p2.mnemonic == 'adrp' and p2.op_str.startswith('x22, #'):
                                    base = int(p2.op_str.split('#')[1], 0)
                                    slot = base + imm
                                    str_va = rels.get(slot, 0)
                                    st = read_str(str_va)
                                    if st:
                                        class_name = st
                                    break
                            if class_name:
                                break
                    if class_name:
                        break

            if not class_name or class_name == "Unknown":
                self.fail(f"Fail-closed: Class attribution failed at call-site {hex(call_site)} for table {hex(table_rva)}")

            reg_sites[table_rva] = {
                'class_name': class_name,
                'call_site': call_site,
                'table_rva': table_rva,
                'count': count
            }

        total_declared = sum(r['count'] for r in reg_sites.values())
        if len(reg_sites) != 14:
            self.fail(f"Expected exactly 14 RegisterNatives call sites, found {len(reg_sites)}")
        if total_declared != 71:
            self.fail(f"Expected exactly 71 declared native methods across registration sites, found {total_declared}")

        return reg_sites

    # --------------------------------------------------------------------------
    # 3. Allocator Multi-Instruction Fingerprint Chain Matcher (libunity.so)
    # --------------------------------------------------------------------------
    def analyze_allocator_patches(self) -> Dict[str, Any]:
        print("[*] Running multi-instruction structural allocator chain matcher across ALL .text...")
        with open(self.unity_so, 'rb') as f:
            elf = ELFFile(f)
            loads = self._get_load_segments(elf)
            text_sec = elf.get_section_by_name('.text')
            if not text_sec:
                self.fail(".text section missing from libunity.so")

            text_data = text_sec.data()
            text_addr = text_sec['sh_addr']

        # Find all candidate RVAs matching each 3-instruction fingerprint
        candidates_per_site: List[List[int]] = []
        for idx, (p, t, n) in enumerate(ALLOCATOR_FINGERPRINTS):
            seq = struct.pack('<3I', p, t, n)
            idx_off = 0
            cands = []
            while True:
                idx_off = text_data.find(seq, idx_off)
                if idx_off == -1: break
                va = text_addr + idx_off + 4
                cands.append(va)
                idx_off += 4

            if not cands:
                self.fail(f"Allocator Site {idx+1} fingerprint not found anywhere in .text!")
            candidates_per_site.append(cands)

        # Enumerate all combinations of candidate chains satisfying strict ordering & offsets
        valid_chains = []
        for chain in itertools.product(*candidates_per_site):
            c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18 = chain
            if not (c2 == c1 + 0x10): continue
            if not (0 < c3 - c2 < 0x1000): continue
            if not (0 < c4 - c3 < 0x3000): continue
            if not (0 < c5 - c4 < 0x3000): continue
            if not (0 < c6 - c5 < 0x1000): continue
            if not (c7 == c6 + 0x2C): continue
            if not (0 < c8 - c7 < 0x2000): continue
            if not (c9 == c8 + 8): continue
            if not (0 < c10 - c9 < 0x200): continue
            if not (0 < c11 - c10 < 0x300): continue
            if not (c12 == c11 + 0x10): continue
            if not (c13 == c12 + 8): continue
            if not (0 < c14 - c13 < 0x100): continue
            if not (c15 == c14 + 4): continue
            if not (c16 == c15 + 4): continue
            if not (0 < c17 - c16 < 0x100): continue
            if not (0 < c18 - c17 < 0x100): continue
            valid_chains.append(chain)

        if len(valid_chains) != 1:
            self.fail(f"Allocator matcher must find exactly 1 unique chain across .text, found {len(valid_chains)}")

        resolved_chain = valid_chains[0]
        patch_table = []
        for idx, rva in enumerate(resolved_chain):
            foff = self._va_to_file_offset(loads, rva)
            patch_table.append({
                "index": idx + 1,
                "rva": hex(rva),
                "from_word": hex(ALLOCATOR_ORIG_WORDS[idx]),
                "to_word": hex(ALLOCATOR_PATCH_WORDS[idx]),
                "desc": ALLOCATOR_DESCRIPTIONS[idx],
                "confidence": "CONFIRMED_STRUCTURAL",
                "evidence": {
                    "virtual_address": hex(rva),
                    "file_offset": hex(foff) if foff is not None else "0x0",
                    "segment_flags": self._get_segment_flags(loads, rva),
                    "fingerprint_3_words": [hex(w) for w in ALLOCATOR_FINGERPRINTS[idx]],
                    "total_candidates_examined": len(candidates_per_site[idx]),
                    "uniqueness_verified": True
                }
            })

        print(f"    -> Exactly 1 valid structural chain found ({hex(resolved_chain[0])}..{hex(resolved_chain[-1])}, 18/18 sites)")
        return {
            "status": "ALL_18_CONFIRMED",
            "count": 18,
            "patch_table": patch_table
        }

    # --------------------------------------------------------------------------
    # 4. IL2CPP JNI Globals Recovery (libil2cpp.so)
    # --------------------------------------------------------------------------
    def analyze_il2cpp_jni(self) -> Dict[str, Any]:
        print("[*] Analyzing libil2cpp.so exported JNI_OnLoad and JNI globals...")
        with open(self.il2cpp_so, 'rb') as f:
            elf = ELFFile(f)
            loads = self._get_load_segments(elf)

            dynsym = elf.get_section_by_name('.dynsym')
            jni_onload_sym = None
            for sym in dynsym.iter_symbols():
                if sym.name == 'JNI_OnLoad':
                    jni_onload_sym = sym
                    break

            if not jni_onload_sym:
                self.fail("JNI_OnLoad symbol not found in libil2cpp.so")

            jni_onload_va = jni_onload_sym['st_value']
            code = self._read_va(f, loads, jni_onload_va, 64)

            # Disassemble first 12 instructions
            dis = list(self.cs_md.disasm(code, jni_onload_va))
            if len(dis) < 8:
                self.fail("Failed to disassemble libil2cpp JNI_OnLoad prologue")

            # Parse instructions in JNI_OnLoad:
            # 1. str x19, [x8, #...] after adrp x8, #... -> JavaVM* cache slot
            # 2. adr x0, #... -> handler function
            # 3. bl #... -> setter function that stores x0 into handler slot
            javavm_cache_slot = None
            handler_fn = None
            setter_target = None

            for i, ins in enumerate(dis):
                if ins.mnemonic == 'str' and 'x19' in ins.op_str:
                    for j in range(i - 1, -1, -1):
                        if dis[j].mnemonic == 'adrp':
                            imm_adrp = int(dis[j].op_str.split(',')[1].strip().lstrip('#'), 16)
                            imm_off = int(ins.op_str.split('#')[1].rstrip(']').strip(), 16)
                            javavm_cache_slot = imm_adrp + imm_off
                            break
                elif ins.mnemonic == 'adr' and ins.op_str.startswith('x0'):
                    handler_fn = int(ins.op_str.split('#')[1].strip(), 16)
                elif ins.mnemonic == 'bl' and handler_fn and not setter_target:
                    setter_target = int(ins.op_str.split('#')[1].strip(), 16)

            if not (javavm_cache_slot and handler_fn and setter_target):
                self.fail("Failed to resolve JNI_OnLoad globals pattern in libil2cpp.so")

            # Inspect setter function to find handler slot
            setter_code = self._read_va(f, loads, setter_target, 32)
            setter_dis = list(self.cs_md.disasm(setter_code, setter_target))
            handler_slot = None
            for i, ins in enumerate(setter_dis):
                if ins.mnemonic == 'str' and 'x0' in ins.op_str:
                    prev = setter_dis[i - 1] if i > 0 else None
                    if prev and prev.mnemonic == 'adrp':
                        imm_adrp = int(prev.op_str.split(',')[1].strip().lstrip('#'), 16)
                        imm_off = int(ins.op_str.split('#')[1].rstrip(']').strip(), 16)
                        handler_slot = imm_adrp + imm_off
                        break

            if not handler_slot:
                self.fail("Failed to resolve JNI handler slot in libil2cpp.so setter function")

            foff_jvm = self._va_to_file_offset(loads, javavm_cache_slot)
            foff_hslot = self._va_to_file_offset(loads, handler_slot)
            foff_hfn = self._va_to_file_offset(loads, handler_fn)

            print(f"    -> JavaVM cache: {hex(javavm_cache_slot)}, Handler slot: {hex(handler_slot)}, Handler fn: {hex(handler_fn)}")
            return {
                "JNI_OnLoad_rva": hex(jni_onload_va),
                "JavaVM_cache_slot": hex(javavm_cache_slot),
                "JNI_handler_slot": hex(handler_slot),
                "JNI_handler_fn": hex(handler_fn),
                "confidence": "CONFIRMED_STRUCTURAL",
                "evidence": {
                    "JavaVM_cache_slot_offset": hex(foff_jvm) if foff_jvm else "0x0",
                    "JNI_handler_slot_offset": hex(foff_hslot) if foff_hslot else "0x0",
                    "JNI_handler_fn_offset": hex(foff_hfn) if foff_hfn else "0x0"
                }
            }

    # --------------------------------------------------------------------------
    # 5. Metadata v39 Resolver: Input & PlayerPrefs Overloads
    # --------------------------------------------------------------------------
    def analyze_metadata_methods(self) -> Dict[str, Any]:
        print("[*] Resolving Input and PlayerPrefs methods via IL2CPP Metadata v39...")
        with open(self.metadata_dat, 'rb') as f:
            meta = Il2CppMetadataV39(f.read())

        resolver = Il2CppMethodResolver(self.il2cpp_so, meta)
        try:
            res = resolver.resolve_target_methods()
        except Exception as e:
            self.fail(f"Failed to resolve IL2CPP metadata methods: {e}")
        print(f"    -> Resolved {len(res['input_methods'])} Input methods, {len(res['playerprefs_methods'])} PlayerPrefs methods with full overloads")
        return res

    # --------------------------------------------------------------------------
    # 6. TimeManager::Update Full Basic Block Semantic Matcher (libunity.so)
    # --------------------------------------------------------------------------
    def analyze_timemanager(self) -> Dict[str, Any]:
        print("[*] Matching TimeManager::Update full basic block and relocation...")
        with open(self.unity_so, 'rb') as f:
            elf = ELFFile(f)
            loads = self._get_load_segments(elf)
            text_sec = elf.get_section_by_name('.text')
            data = text_sec.data()
            text_addr = text_sec['sh_addr']

            # All 14 instructions: 9 instructions entry block + 5 instructions body block
            tm_sequence_words = [
                0xf940b008,  # 0: ldr x8, [x0, #0x160]
                0xb9416809,  # 1: ldr w9, [x0, #0x168]
                0x3946a00a,  # 2: ldrb w10, [x0, #0x1a8]
                0x91000508,  # 3: add x8, x8, #1
                0x11000529,  # 4: add w9, w9, #1
                0xf900b008,  # 5: str x8, [x0, #0x160]
                0xb9016809,  # 6: str w9, [x0, #0x168]
                0x3400004a,  # 7: cbz w10, #+0x8 (target = body)
                0xd65f03c0,  # 8: ret
                0xd10243ff,  # 9: sub sp, sp, #0x90
                0x6d0723e9,  # 10: stp d9, d8, [sp, #0x70]
                0xa9084ffe,  # 11: stp x30, x19, [sp, #0x80]
                0x1e604008,  # 12: fmov d8, d0
                0xaa0003f3   # 13: mov x19, x0
            ]
            seq = struct.pack('<14I', *tm_sequence_words)
            idx = 0
            matches = []
            while True:
                idx = data.find(seq, idx)
                if idx == -1: break
                va = text_addr + idx
                # Check preceding instruction is tail-call boundary (b instruction)
                prev_w = struct.unpack('<I', data[idx - 4: idx])[0]
                if (prev_w & 0xFC000000) == 0x14000000 or prev_w == 0xD65F03C0:
                    matches.append((va, prev_w))
                idx += 4

            if len(matches) != 1:
                self.fail(f"TimeManager::Update matching must yield exactly 1 candidate, found {len(matches)}")

            entry_va = matches[0][0]
            body_va = entry_va + 0x24

            # Verify relocation in .rela.dyn
            rela = elf.get_section_by_name('.rela.dyn')
            reloc_found = False
            reloc_slot = None
            for r in rela.iter_relocations():
                if r['r_addend'] == entry_va:
                    reloc_found = True
                    reloc_slot = r['r_offset']
                    break

            if not reloc_found:
                self.fail(f"Relocation entry pointing to TimeManager::Update (0x{entry_va:x}) not found in .rela.dyn")

            foff_entry = self._va_to_file_offset(loads, entry_va)
            foff_body = self._va_to_file_offset(loads, body_va)

            print(f"    -> TimeManager::Update entry: {hex(entry_va)}, body: {hex(body_va)} (vtable reloc at {hex(reloc_slot)})")
            return {
                "entry_rva": hex(entry_va),
                "body_rva": hex(body_va),
                "field_frame_count": "0x160 (u64)",
                "field_aux": "0x168 (u32)",
                "field_pause": "0x1a8 (u8)",
                "confidence": "CONFIRMED_SEMANTIC",
                "evidence": {
                    "virtual_address": hex(entry_va),
                    "file_offset": hex(foff_entry) if foff_entry else "0x0",
                    "body_file_offset": hex(foff_body) if foff_body else "0x0",
                    "segment_flags": self._get_segment_flags(loads, entry_va),
                    "vtable_relocation_slot": hex(reloc_slot),
                    "matched_instructions_count": len(tm_sequence_words),
                    "uniqueness_verified": True
                }
            }

    # --------------------------------------------------------------------------
    # 7. Choreographer & Vsync Pacing Status (Deferred to Hardware Gate)
    # --------------------------------------------------------------------------
    def analyze_choreographer_vsync(self) -> Dict[str, Any]:
        print("[*] Analyzing Choreographer and Vsync pacing hooks...")
        # Per M1 instructions, do not emit fake or unproven hardcoded addresses
        return {
            "status": "UNRESOLVED_REQUIRES_HARDWARE_VALIDATION",
            "confidence": "UNVERIFIED_RUNTIME_HOOK",
            "notes": "Choreographer and Vsync presentation hooks deferred to runtime hardware gate. No hardcoded RVAs emitted in production header.",
            "emitted_offsets": None
        }

    # --------------------------------------------------------------------------
    # Run Orchestration & Strict Schema Validation
    # --------------------------------------------------------------------------
    def run_all(self) -> Dict[str, Any]:
        self.results["findings"]["identities"] = self.verify_target_identities()
        self.results["findings"]["unity_natives"] = self.analyze_unity_natives()
        self.results["findings"]["memory_region_patches"] = self.analyze_allocator_patches()
        self.results["findings"]["il2cpp_jni_globals"] = self.analyze_il2cpp_jni()
        self.results["findings"]["il2cpp_metadata_methods"] = self.analyze_metadata_methods()
        self.results["findings"]["timemanager_clock"] = self.analyze_timemanager()
        self.results["findings"]["choreographer_vsync"] = self.analyze_choreographer_vsync()

        # Fail-closed schema check before finalizing
        f = self.results["findings"]
        if f["unity_natives"]["total_methods"] != 71:
            self.fail(f"Schema check failed: RegisterNatives method count != 71 (found {f['unity_natives']['total_methods']})")
        if len(f["unity_natives"]["tables"]) != 14:
            self.fail(f"Schema check failed: RegisterNatives table count != 14 (found {len(f['unity_natives']['tables'])})")
        if f["memory_region_patches"]["count"] != 18:
            self.fail("Schema check failed: Allocator patch count != 18")
        if len(f["il2cpp_metadata_methods"]["playerprefs_methods"]) != 17:
            self.fail("Schema check failed: PlayerPrefs method count != 17")
        if not f["il2cpp_metadata_methods"]["evidence"]["abi_get_touch"]["verified_in_disassembly"]:
            self.fail("Schema check failed: Touch ABI not verified in disassembly")

        self.results["status"] = "SUCCESS" if self.integrity_verified else "TEST_ONLY_UNVERIFIED"
        self.results["integrity_verified"] = self.integrity_verified
        return self.results


# ------------------------------------------------------------------------------
# Report & C Header Generation
# ------------------------------------------------------------------------------
def generate_c_header(results: Dict[str, Any], header_path: str):
    if not results.get("integrity_verified", False) or results.get("status") != "SUCCESS":
        raise RuntimeError("Cannot generate production C header for unverified or test-only artifacts!")

    with open(header_path, 'w', encoding='utf-8') as f:
        f.write("/* AUTO-GENERATED BY durak_analyzer.py for Durak 25.0 (ru.appscraft.durak) */\n")
        f.write("/* Milestone M1: Verified target offsets and evidence. Do not edit manually. */\n")
        f.write("#ifndef DURAK_RECOVERED_OFFSETS_H\n#define DURAK_RECOVERED_OFFSETS_H\n\n")

        f.write("/* ---- Target Build Identity ---- */\n")
        f.write('#define DURAK_PACKAGE_NAME               "ru.appscraft.durak"\n')
        f.write('#define DURAK_VERSION_NAME               "25.0"\n')
        f.write('#define DURAK_VERSION_CODE               250\n')
        f.write('#define DURAK_LIBUNITY_BUILD_ID          "bcc661ea2046416d"\n')
        f.write('#define DURAK_LIBIL2CPP_BUILD_ID         "d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0"\n\n')

        f.write("/* ---- Unity Lifecycle & JNI Natives (libunity.so) [CONFIRMED with Class Ownership] ---- */\n")
        natives = results["findings"]["unity_natives"]["lifecycle_entrypoints"]
        for name, info in sorted(natives.items()):
            f.write(f"#define OFF_{name:<32} {info['rva']} /* {info.get('registered_class', '')} */\n")

        f.write("\n/* ---- FMOD Natives (libunity.so) [CONFIRMED] ---- */\n")
        fmod = results["findings"]["unity_natives"]["fmod_natives"]
        for name, info in sorted(fmod.items()):
            f.write(f"#define OFF_{name:<32} {info['rva']} /* {info.get('registered_class', '')} */\n")

        f.write("\n/* ---- TimeManager::Update (libunity.so) [CONFIRMED_SEMANTIC] ---- */\n")
        tm = results["findings"]["timemanager_clock"]
        f.write(f"#define OFF_TimeManager_Update_entry     {tm['entry_rva']}\n")
        f.write(f"#define OFF_TimeManager_Update_body      {tm['body_rva']}\n")
        f.write(f"#define TM_FIELD_FRAMECOUNT              0x160\n")
        f.write(f"#define TM_FIELD_AUX                     0x168\n")
        f.write(f"#define TM_FIELD_PAUSE                   0x1a8\n")

        f.write("\n/* ---- IL2CPP JNI Globals (libil2cpp.so) [CONFIRMED] ---- */\n")
        jni = results["findings"]["il2cpp_jni_globals"]
        f.write(f"#define OFF_IL2CPP_JNI_OnLoad            {jni['JNI_OnLoad_rva']}\n")
        f.write(f"#define OFF_IL2CPP_JavaVM_cache          {jni['JavaVM_cache_slot']}\n")
        f.write(f"#define OFF_IL2CPP_JNI_handler_slot      {jni['JNI_handler_slot']}\n")
        f.write(f"#define OFF_IL2CPP_JNI_handler_fn        {jni['JNI_handler_fn']}\n")

        f.write("\n/* ---- Input Methods (libil2cpp.so) [CONFIRMED] ---- */\n")
        inp = results["findings"]["il2cpp_metadata_methods"]["input_methods"]
        for name in ("get_touchCount", "get_mousePosition", "GetMouseButton", "GetMouseButtonDown", "GetMouseButtonUp", "GetTouch"):
            if name in inp:
                f.write(f"#define RVA_Input_{name:<23} {inp[name]['rva']}\n")

        f.write("\n/* ---- PlayerPrefs Methods (libil2cpp.so) [CONFIRMED with Full Overloads] ---- */\n")
        pp = results["findings"]["il2cpp_metadata_methods"]["playerprefs_methods"]
        for name in ("SetInt", "GetInt1", "GetInt2", "SetString", "GetString1", "GetString2", "HasKey", "DeleteKey", "Save"):
            if name in pp:
                f.write(f"#define RVA_PlayerPrefs_{name:<18} {pp[name]['rva']}\n")

        f.write("\n/* ---- Allocator 256MB->64MB Region Granularity Patches (libunity.so) [CONFIRMED] ---- */\n")
        patches = results["findings"]["memory_region_patches"]["patch_table"]
        f.write("static const struct { uint32_t off, from, to; } DURAK_REGION_PATCH[] = {\n")
        for p in patches:
            f.write(f"  {{{p['rva']}, {p['from_word']}, {p['to_word']}}}, /* {p['desc']} */\n")
        f.write("};\n")
        f.write("#define DURAK_REGION_PATCH_N ((int)(sizeof(DURAK_REGION_PATCH)/sizeof(DURAK_REGION_PATCH[0])))\n\n")

        f.write("#endif /* DURAK_RECOVERED_OFFSETS_H */\n")


def generate_markdown_summary(results: Dict[str, Any], md_path: str):
    if not results.get("integrity_verified", False) or results.get("status") != "SUCCESS":
        raise RuntimeError("Cannot generate production markdown report for unverified or test-only artifacts!")

    with open(md_path, 'w', encoding='utf-8') as f:
        f.write("# Звіт Milestone M1: Verified Target and Evidence\n\n")
        f.write("Цей звіт сформовано інструментом `durak_analyzer.py` (fail-closed).\n")
        f.write("Кожна адреса отримана через структурні докази (ELF relocations, IL2CPP metadata v39, ARM64 disassembly).\n\n")

        f.write("## 1. Ідентифікація та цілісність бінарних файлів\n\n")
        f.write("| Файл | Розмір (bytes) | GNU Build ID | SHA-256 |\n")
        f.write("|---|---:|---|---|\n")
        bins = results["findings"]["identities"]["binaries"]
        for fn, b in bins.items():
            f.write(f"| `{fn}` | {b['size']} | `{b['build_id']}` | `{b['sha256'][:16]}...` |\n")

        meta = results["findings"]["identities"]["metadata"]
        f.write(f"\n- **global-metadata.dat**: розмір {meta['size']} bytes, версія {meta['version']}, magic `{meta['magic']}`, SHA-256 `{meta['sha256'][:16]}...`.\n\n")

        f.write("## 2. Unity RegisterNatives та Lifecycle RVA (`libunity.so`)\n\n")
        f.write("Доведено прив'язку таблиць нативних методів до конкретних Java-класів через трасування call-sites `RegisterNatives` у `JNI_OnLoad`:\n\n")
        f.write("| Метод | Сигнатура | Java Class | Call-Site RVA | RVA Durak 25.0 |\n")
        f.write("|---|---|---|---:|---:|\n")
        lc = results["findings"]["unity_natives"]["lifecycle_entrypoints"]
        for name in sorted(lc.keys()):
            f.write(f"| `{name}` | `{lc[name]['signature']}` | `{lc[name].get('registered_class', '')}` | `{lc[name].get('registration_call_site', '')}` | `0x{int(lc[name]['rva'], 16):X}` |\n")
        fm = results["findings"]["unity_natives"]["fmod_natives"]
        for name in sorted(fm.keys()):
            f.write(f"| `[FMOD] {name}` | `{fm[name]['signature']}` | `{fm[name].get('registered_class', '')}` | `{fm[name].get('registration_call_site', '')}` | `0x{int(fm[name]['rva'], 16):X}` |\n")

        f.write("\n## 3. Memory Region Granularity Patches (256MB -> 64MB)\n\n")
        f.write("Усі 18 інструкцій локалізовано через **multi-instruction fingerprint matching** по всій секції `.text`:\n\n")
        f.write("| # | RVA | From (256MB) | To (64MB) | Опис |\n")
        f.write("|---|---:|---:|---:|---|\n")
        pt = results["findings"]["memory_region_patches"]["patch_table"]
        for p in pt:
            f.write(f"| {p['index']} | `0x{int(p['rva'], 16):X}` | `{p['from_word']}` | `{p['to_word']}` | {p['desc']} |\n")

        f.write("\n## 4. IL2CPP JNI Globals (`libil2cpp.so`)\n\n")
        jni = results["findings"]["il2cpp_jni_globals"]
        f.write(f"- `JNI_OnLoad` export: `0x{int(jni['JNI_OnLoad_rva'], 16):X}`\n")
        f.write(f"- `JavaVM*` cache global: `0x{int(jni['JavaVM_cache_slot'], 16):X}`\n")
        f.write(f"- JNI handler slot global: `0x{int(jni['JNI_handler_slot'], 16):X}`\n")
        f.write(f"- JNI handler function: `0x{int(jni['JNI_handler_fn'], 16):X}`\n")

        f.write("\n## 5. IL2CPP Metadata v39: Input & PlayerPrefs з канонічними сигнатурами\n\n")
        f.write("### Input методи:\n\n")
        f.write("| Метод | Сигнатура | RID | RVA Durak 25.0 |\n")
        f.write("|---|---|---:|---:|\n")
        inp = results["findings"]["il2cpp_metadata_methods"]["input_methods"]
        for name in ("get_touchCount", "get_mousePosition", "GetMouseButton", "GetMouseButtonDown", "GetMouseButtonUp", "GetTouch"):
            if name in inp:
                f.write(f"| `UnityEngine.Input::{name}` | `{inp[name].get('canonical_signature', '')}` | {inp[name]['rid']} | `0x{int(inp[name]['rva'], 16):X}` |\n")

        f.write("\n### PlayerPrefs методи (роздільні перевантаження):\n\n")
        f.write("| Метод | Канонічна сигнатура | RID | RVA Durak 25.0 |\n")
        f.write("|---|---|---:|---:|\n")
        pp = results["findings"]["il2cpp_metadata_methods"]["playerprefs_methods"]
        for name in ("SetInt", "GetInt1", "GetInt2", "SetString", "GetString1", "GetString2", "HasKey", "DeleteKey", "Save"):
            if name in pp:
                f.write(f"| `PlayerPrefs::{name}` | `{pp[name].get('canonical_signature', '')}` | {pp[name]['rid']} | `0x{int(pp[name]['rva'], 16):X}` |\n")

        f.write("\n### ABI Analysis & Engine Stripping Evidence:\n\n")
        ev = results["findings"]["il2cpp_metadata_methods"]["evidence"]
        cs = ev["code_stripping"]
        f.write(f"- **PlayerPrefs code stripping**: `has_set_float = {cs['has_set_float']}`, `has_get_float = {cs['has_get_float']}`. Доказ: {cs['proof']}\n")
        abi = ev["abi_get_touch"]
        f.write(f"- **`UnityEngine.Touch` return ABI**: {abi['indirect_result_register']}, розмір структури {abi['return_struct']}, регістр індексу {abi['index_parameter_register']}. Перевірено у машинному коді: {abi['verified_in_disassembly']}.\n")
        f.write(f"- **Memcpy PLT Stub Target**: `{abi.get('memcpy_plt_target')}` -> Symbol `{abi.get('memcpy_resolved_symbol')}`.\n")

        f.write("\n## 6. Engine Clock: `TimeManager::Update`\n\n")
        tm = results["findings"]["timemanager_clock"]
        f.write(f"- Entry RVA: `0x{int(tm['entry_rva'], 16):X}`\n")
        f.write(f"- Body RVA: `0x{int(tm['body_rva'], 16):X}`\n")
        f.write(f"- Зміщення: frameCount=`+{tm['field_frame_count']}`, aux=`+{tm['field_aux']}`, pause=`+{tm['field_pause']}`\n")
        f.write(f"- Relocation slot: `{tm['evidence']['vtable_relocation_slot']}`\n")

        f.write("\n## 7. Невстановлені точки / Потребують Hardware Gate\n\n")
        ch = results["findings"]["choreographer_vsync"]
        f.write(f"- **Choreographer / Vsync**: Статус: `{ch['status']}`. Примітки: {ch['notes']}\n")
        f.write(f"- **FMOD setOutput**: відкладено до аудіо етапу.\n")


def main():
    parser = argparse.ArgumentParser(description="Durak NX Fail-Closed Analyzer (Milestone M1)")
    parser.add_argument("--data-dir", default="extracted_durak", help="Directory containing extracted binaries")
    parser.add_argument("--json", default="docs/analysis/durak_rva_report.json", help="Output JSON report")
    parser.add_argument("--header", default="docs/analysis/durak_recovered_offsets.h", help="Output C header")
    parser.add_argument("--markdown", default="docs/analysis/durak_analysis_summary.md", help="Output Markdown report")
    args = parser.parse_args()

    analyzer = DurakFailClosedAnalyzer(args.data_dir, test_mode=False)
    try:
        results = analyzer.run_all()
        if not results.get("integrity_verified", False) or results.get("status") != "SUCCESS":
            raise RuntimeError("Analysis completed without verified integrity status")
    except Exception as e:
        # Fail closed: remove incomplete or stale header
        if os.path.exists(args.header):
            os.remove(args.header)
        print(f"\n[!] ANALYSIS FAILED CLOSED: {e}", file=sys.stderr)
        sys.exit(1)

    with open(args.json, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Full JSON written to: {args.json}")

    generate_markdown_summary(results, args.markdown)
    print(f"[+] Markdown report written to: {args.markdown}")

    generate_c_header(results, args.header)
    print(f"[+] C header written to: {args.header}\n")


if __name__ == '__main__':
    main()
