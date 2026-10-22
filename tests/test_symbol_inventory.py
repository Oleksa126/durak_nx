#!/usr/bin/env python3
"""
tests/test_symbol_inventory.py - Unit test suite for canonical symbol inventory generator.

Tests:
1. Direct in-memory ELF parsing and linking producing exact 362 strong / 631 sites / 4 weak + .dynsym st_type.
2. Deterministic regeneration in isolated temporary directories (does not write to REPO_ROOT).
3. Fail-closed behavior on mutated SHA-256.
4. Fail-closed behavior on mutated Build-ID.
5. Fail-closed behavior on missing core library.
6. Fail-closed execution (`SystemExit(1)`) on tampered/stale reference JSON with mutated relocation offset.
7. Fail-closed execution (`SystemExit(1)`) on missing symbol metadata entry.
8. Fail-closed execution (`SystemExit(1)`) on symbol type mismatch (`STT_FUNC` vs `STT_OBJECT` against `.dynsym`).
9. Bionic __FD_*_chk ABI signature validation (3 parameters including size_t set_size).
10. Strict Wave 1 purity: 27 pure stateless, locale-independent leaf functions (45 sites), zero implicit/explicit locale or RNG state.
11. 100% accounting of all 362 symbols across the 10 waves summing to 631 sites with NDK reference and unverified ctor status.
"""

import os
import sys
import json
import copy
import shutil
import hashlib
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.generate_symbol_inventory import (
    SYMBOL_METADATA,
    EXPECTED_CORE_LIBRARIES,
    NDK_API_REFERENCE,
    verify_target_binaries,
    compute_unresolved_relocations_from_elf,
    verify_against_reference_json,
    validate_and_filter_metadata,
    generate_inventory
)


class TestCanonicalSymbolInventory(unittest.TestCase):

    def setUp(self):
        self.data_dir = REPO_ROOT / "extracted_durak"
        self.assertTrue(self.data_dir.is_dir(), f"Missing extracted_durak at {self.data_dir}")

    def test_01_canonical_inventory_generation_from_elf_direct(self):
        """Verify direct in-memory calculation yields 362 strong symbols / 631 sites / 4 weak + dynsym types."""
        strong_details, weak_details, sym_elf_types = compute_unresolved_relocations_from_elf(self.data_dir)
        
        self.assertEqual(len(strong_details), 631, f"Expected 631 strong relocation sites, got {len(strong_details)}")
        self.assertEqual(len(weak_details), 4, f"Expected 4 weak relocation sites, got {len(weak_details)}")
        
        unique_strong = set(x["symbol"] for x in strong_details)
        self.assertEqual(len(unique_strong), 362, f"Expected 362 unique strong symbols, got {len(unique_strong)}")
        self.assertEqual(len(sym_elf_types), 362)
        
        # Verify exact STT_FUNC / STT_OBJECT distribution in .dynsym
        func_count = sum(1 for t in sym_elf_types.values() if t == "STT_FUNC")
        obj_count = sum(1 for t in sym_elf_types.values() if t == "STT_OBJECT")
        self.assertEqual(func_count, 359)
        self.assertEqual(obj_count, 3)
        
        # Verify weak symbols identity
        weak_syms = set(x["symbol"] for x in weak_details)
        self.assertEqual(weak_syms, {"pthread_create", "_ZTH15gDeferredAction", "AChoreographer_postFrameCallback64"})

    def test_02_deterministic_regeneration_in_temp_dir(self):
        """Verify running inventory generator into temporary directories produces byte-for-byte identical files."""
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            out1 = Path(tmp1)
            out2 = Path(tmp2)
            
            generate_inventory(extracted_dir=self.data_dir, output_dir=out1)
            generate_inventory(extracted_dir=self.data_dir, output_dir=out2)
            
            json1 = (out1 / "durak_362_unresolved_inventory.json").read_bytes()
            json2 = (out2 / "durak_362_unresolved_inventory.json").read_bytes()
            md1 = (out1 / "durak_362_unresolved_inventory.md").read_bytes()
            md2 = (out2 / "durak_362_unresolved_inventory.md").read_bytes()
            
            self.assertEqual(json1, json2, "JSON inventory output is non-deterministic!")
            self.assertEqual(md1, md2, "Markdown report output is non-deterministic!")

    def test_03_fail_closed_on_sha256_mutation(self):
        """Verify verify_target_binaries fails closed (SystemExit 1) if 1 byte in a .so is altered."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            for name in EXPECTED_CORE_LIBRARIES:
                shutil.copy2(self.data_dir / name, tmp_path / name)
            
            target = tmp_path / "libmain.so"
            data = bytearray(target.read_bytes())
            data[0x100] ^= 0x55
            target.write_bytes(data)
            
            with self.assertRaises(SystemExit) as ctx:
                verify_target_binaries(tmp_path)
            self.assertEqual(ctx.exception.code, 1)

    def test_04_fail_closed_on_build_id_mutation(self):
        """Verify verify_target_binaries fails closed specifically when Build-ID note does not match."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            for name in EXPECTED_CORE_LIBRARIES:
                shutil.copy2(self.data_dir / name, tmp_path / name)
            
            target = tmp_path / "libmain.so"
            data = bytearray(target.read_bytes())
            bid_str = EXPECTED_CORE_LIBRARIES["libmain.so"]["build_id"]
            bid_bytes = bytes.fromhex(bid_str)
            idx = data.find(bid_bytes)
            self.assertNotEqual(idx, -1, "Could not locate Build-ID in libmain.so")
            
            data[idx] ^= 0xFF
            target.write_bytes(data)

            mutated_sha = hashlib.sha256(data).hexdigest()
            orig_sha = EXPECTED_CORE_LIBRARIES["libmain.so"]["sha256"]
            try:
                EXPECTED_CORE_LIBRARIES["libmain.so"]["sha256"] = mutated_sha
                with self.assertRaises(SystemExit) as ctx:
                    verify_target_binaries(tmp_path)
                self.assertEqual(ctx.exception.code, 1)
            finally:
                EXPECTED_CORE_LIBRARIES["libmain.so"]["sha256"] = orig_sha

    def test_05_fail_closed_on_missing_binary(self):
        """Verify verify_target_binaries fails closed if any core library is missing."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            for name in ["libmain.so", "libunity.so", "libil2cpp.so"]:
                shutil.copy2(self.data_dir / name, tmp_path / name)
            
            with self.assertRaises(SystemExit) as ctx:
                verify_target_binaries(tmp_path)
            self.assertEqual(ctx.exception.code, 1)

    def test_06_fail_closed_on_forged_reference_json_offset(self):
        """Verify generate_inventory fails closed (SystemExit 1) when given a forged JSON with altered offset."""
        orig_json_path = REPO_ROOT / "docs" / "analysis" / "durak_unresolved_imports.json"
        self.assertTrue(orig_json_path.is_file())
        
        with open(orig_json_path, "r", encoding="utf-8") as f:
            forged_data = json.load(f)
            
        # Mutate RVA offset of the first relocation entry
        forged_data["unresolved_strong_details"][0]["r_offset"] = "0xdeadbeef"
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            forged_json_path = tmp_path / "forged_unresolved_imports.json"
            with open(forged_json_path, "w", encoding="utf-8") as f:
                json.dump(forged_data, f)
                
            with self.assertRaises(SystemExit) as ctx:
                generate_inventory(
                    extracted_dir=self.data_dir,
                    output_dir=tmp_path,
                    reference_json_path=forged_json_path
                )
            self.assertEqual(ctx.exception.code, 1)

    def test_07_fail_closed_on_missing_metadata_entry(self):
        """Verify generate_inventory fails closed (SystemExit 1) if a symbol is missing from metadata_db."""
        incomplete_meta = copy.deepcopy(SYMBOL_METADATA)
        del incomplete_meta["bsearch"]
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            with self.assertRaises(SystemExit) as ctx:
                generate_inventory(
                    extracted_dir=self.data_dir,
                    output_dir=Path(tmp_dir),
                    metadata_db=incomplete_meta
                )
            self.assertEqual(ctx.exception.code, 1)

    def test_08_fail_closed_on_symbol_type_mismatch_against_dynsym(self):
        """Verify generate_inventory fails closed (SystemExit 1) if symbol type mismatches ELF .dynsym."""
        corrupt_type_meta = copy.deepcopy(SYMBOL_METADATA)
        # bsearch is STT_FUNC in .dynsym; corrupt it to STT_OBJECT
        corrupt_type_meta["bsearch"]["type"] = "STT_OBJECT"
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            with self.assertRaises(SystemExit) as ctx:
                generate_inventory(
                    extracted_dir=self.data_dir,
                    output_dir=Path(tmp_dir),
                    metadata_db=corrupt_type_meta
                )
            self.assertEqual(ctx.exception.code, 1)

    def test_09_bionic_select_chk_signatures_three_parameters(self):
        """Verify __FD_ISSET_chk, __FD_SET_chk, __FD_CLR_chk have 3 parameters with size_t set_size."""
        self.assertEqual(
            SYMBOL_METADATA["__FD_ISSET_chk"]["sig"],
            "int __FD_ISSET_chk(int fd, const fd_set* set, size_t set_size);"
        )
        self.assertEqual(
            SYMBOL_METADATA["__FD_SET_chk"]["sig"],
            "void __FD_SET_chk(int fd, fd_set* set, size_t set_size);"
        )
        self.assertEqual(
            SYMBOL_METADATA["__FD_CLR_chk"]["sig"],
            "void __FD_CLR_chk(int fd, fd_set* set, size_t set_size);"
        )

    def test_10_wave_1_safe_leaf_purity_and_statelessness(self):
        """Verify Wave 1 contains strictly 27 stateless, locale-independent leaf functions (45 sites)."""
        with open(REPO_ROOT / "docs" / "analysis" / "durak_362_unresolved_inventory.json", "r", encoding="utf-8") as f:
            inventory = json.load(f)
            
        w1_symbols = [s for s in inventory["symbols"] if s["wave"] == "Wave 1 (Safe Leaf Libc & Math)"]
        self.assertEqual(len(w1_symbols), 27, f"Expected 27 pure Wave 1 symbols, got {len(w1_symbols)}")
        w1_sites = sum(s["total_sites"] for s in w1_symbols)
        self.assertEqual(w1_sites, 45, f"Expected 45 Wave 1 sites, got {w1_sites}")
        
        allowed_w1_headers = {"<stdlib.h>", "<math.h>", "<string.h>", "<wchar.h>"}
        forbidden_w1_names = {
            "islower", "isspace", "isxdigit", "strcasecmp", "strtold", "towlower",
            "wcstod", "wcstof", "wcstol", "wcstold", "wcstoll", "wcstoul", "wcstoull",
            "lrand48", "srand48", "basename"
        }
        
        for s in w1_symbols:
            name = s["symbol"]
            sig = s["signature"]
            hdr = s["header"]
            self.assertIn(hdr, allowed_w1_headers, f"Disallowed header {hdr} in Wave 1 for {name}")
            self.assertNotIn(name, forbidden_w1_names, f"Locale-sensitive or stateful symbol {name} in Wave 1")
            self.assertFalse(name.endswith("_l"), f"Wave 1 symbol '{name}' has locale suffix _l")
            if name.startswith("strto"):
                self.assertEqual(name, "strtok_r", f"Wave 1 symbol '{name}' is locale-dependent strto*")
            self.assertFalse(name.startswith("wcsto"), f"Wave 1 symbol '{name}' is locale-dependent wcsto*")
            self.assertNotIn("rand", name, f"Wave 1 symbol '{name}' is stateful RNG")
            self.assertNotIn("locale_t", sig)
            self.assertNotIn("mbstate_t", sig)

        # Verify Locale & Multibyte Subsystem (Wave 4) contains 48 symbols across 65 sites
        w4_symbols = [s for s in inventory["symbols"] if s["wave"] == "Wave 4 (Locale & Multibyte Subsystem)"]
        self.assertEqual(len(w4_symbols), 48, f"Expected 48 Wave 4 symbols, got {len(w4_symbols)}")
        w4_sites = sum(s["total_sites"] for s in w4_symbols)
        self.assertEqual(w4_sites, 65, f"Expected 65 Wave 4 sites, got {w4_sites}")

    def test_11_all_362_symbols_accounted_for_and_metadata_honesty(self):
        """Verify all 362 symbols belong to 10 waves, sum to 631 sites, and include NDK/dynsym metadata."""
        with open(REPO_ROOT / "docs" / "analysis" / "durak_362_unresolved_inventory.json", "r", encoding="utf-8") as f:
            inventory = json.load(f)
            
        meta = inventory["metadata"]
        self.assertEqual(meta["ndk_api_reference"], NDK_API_REFERENCE)
        self.assertEqual(meta["prototype_verification_status"], "dynsym_st_type_verified_manual_c_prototype_catalog")
        self.assertEqual(meta["constructor_reachability_status"], "unverified_static_analysis")
        
        symbols = inventory["symbols"]
        self.assertEqual(len(symbols), 362)
        self.assertEqual(sum(s["total_sites"] for s in symbols), 631)
        
        for s in symbols:
            self.assertEqual(s["constructor_reachability"], "unverified")
            self.assertTrue(s["dynsym_verified"])
            self.assertEqual(s["ndk_api_reference"], NDK_API_REFERENCE)
            
        waves = set(s["wave"] for s in symbols)
        self.assertEqual(len(waves), 10)
        for i in range(1, 11):
            matching = [w for w in waves if w.startswith(f"Wave {i} (")]
            self.assertEqual(len(matching), 1, f"Missing wave prefix: Wave {i}")

    def test_12_repository_artifacts_are_fresh_and_match_generator(self):
        """Verify that committed repository root artifacts match freshly generated output byte-for-byte."""
        repo_json = REPO_ROOT / "docs" / "analysis" / "durak_362_unresolved_inventory.json"
        repo_md = REPO_ROOT / "docs" / "analysis" / "durak_362_unresolved_inventory.md"
        self.assertTrue(repo_json.is_file(), f"Missing {repo_json}")
        self.assertTrue(repo_md.is_file(), f"Missing {repo_md}")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            generate_inventory(extracted_dir=self.data_dir, output_dir=tmp_path)
            
            fresh_json = (tmp_path / "durak_362_unresolved_inventory.json").read_bytes()
            fresh_md = (tmp_path / "durak_362_unresolved_inventory.md").read_bytes()
            
            self.assertEqual(
                repo_json.read_bytes(),
                fresh_json,
                "durak_362_unresolved_inventory.json in docs/analysis is stale! Run tools/generate_symbol_inventory.py."
            )
            self.assertEqual(
                repo_md.read_bytes(),
                fresh_md,
                "durak_362_unresolved_inventory.md in docs/analysis is stale! Run tools/generate_symbol_inventory.py."
            )


if __name__ == "__main__":
    unittest.main()

