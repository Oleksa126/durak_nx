#!/usr/bin/env python3
"""
test_m1_fail_closed.py - Comprehensive Unit & Negative Mutation Test Suite for Milestone M1

Covers:
  - Extractor normal verification & fail-closed gates (APKS hash, package, versionName, versionCode)
  - Analyzer normal run & full schema verification
  - Missing file fail-closed gate
  - Build-ID mismatch fail-closed gate
  - Metadata magic & version corruption fail-closed gates
  - Binary SHA-256 mutation fail-closed gate (byte flipped without changing build-id)
  - CLI cannot bypass fail-closed gate (--skip-sha-check removed from CLI)
  - Production artifact generation gate (fails on unverified / test-only run)
  - TimeManager::Update semantic instruction mutation fail-closed gate
  - Allocator 18-instruction chain mutation fail-closed gate
  - IL2CPP JNI Globals pattern mutation fail-closed gate
  - Unity RegisterNatives table corruption fail-closed gate
  - CodeGenModule null method pointer relocation fail-closed gate
  - Touch ABI disassembly & struct size mutation fail-closed gate
  - Touch ABI memcpy PLT branch instruction mutation fail-closed gate (Finding 2)
  - PlayerPrefs parameter type signature mutation fail-closed gate (Finding 3)
  - RegisterNatives Java class attribution and call-site verification (Finding 4)
"""

import unittest
import os
import sys
import shutil
import subprocess
import tempfile
import json
import struct

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_DIR = os.path.join(WORKSPACE_ROOT, "tools")
sys.path.insert(0, TOOLS_DIR)

from durak_analyzer import DurakFailClosedAnalyzer, generate_c_header, generate_markdown_summary

ANALYZER_SCRIPT = os.path.join(TOOLS_DIR, "durak_analyzer.py")
EXTRACTOR_SCRIPT = os.path.join(TOOLS_DIR, "extract_game.py")
DATA_DIR = os.path.join(WORKSPACE_ROOT, "extracted_durak")
APKS_PATH = os.path.join(WORKSPACE_ROOT, "Durak_25.0.apks")


class TestMilestoneM1(unittest.TestCase):

    def _setup_mock_data(self, tmpdir: str) -> str:
        mock_data = os.path.join(tmpdir, "mock_data")
        os.makedirs(mock_data, exist_ok=True)
        for fn in ["libmain.so", "libunity.so", "libil2cpp.so", "libsqlite3.so", "global-metadata.dat", "game_manifest.json"]:
            src = os.path.join(DATA_DIR, fn)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(mock_data, fn))
        return mock_data

    # --------------------------------------------------------------------------
    # 1. Extractor Tests (Normal and Negative Mutations)
    # --------------------------------------------------------------------------
    def test_01_extractor_verify_only_normal(self):
        """Verify extractor --verify-only succeeds on valid APKS bundle."""
        cmd = ["python", EXTRACTOR_SCRIPT, "--verify-only", "--apks", APKS_PATH]
        res = subprocess.run(cmd, cwd=WORKSPACE_ROOT, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"extract_game.py failed:\n{res.stderr}")
        self.assertIn("ru.appscraft.durak", res.stdout)
        self.assertIn("25.0", res.stdout)
        self.assertIn("code 250", res.stdout)

    def test_02_extractor_fail_on_corrupt_apks_hash(self):
        """Verify extractor fails closed when APKS SHA-256 does not match."""
        with tempfile.TemporaryDirectory() as tmpdir:
            corrupt_apks = os.path.join(tmpdir, "corrupt.apks")
            with open(APKS_PATH, "rb") as f_in, open(corrupt_apks, "wb") as f_out:
                f_out.write(f_in.read(1024))
                f_out.write(b"\x00" * 1024)

            cmd = ["python", EXTRACTOR_SCRIPT, "--verify-only", "--apks", corrupt_apks]
            res = subprocess.run(cmd, cwd=WORKSPACE_ROOT, capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0, "Extractor should fail on APKS SHA mismatch")
            self.assertIn("APKS SHA-256 mismatch", res.stderr)

    # --------------------------------------------------------------------------
    # 2. Analyzer Normal Run & Schema Verification
    # --------------------------------------------------------------------------
    def test_03_analyzer_normal_run(self):
        """Verify normal analyzer execution generates valid header and json report with full evidence."""
        with tempfile.TemporaryDirectory() as tmpdir:
            json_out = os.path.join(tmpdir, "test_rva.json")
            header_out = os.path.join(tmpdir, "test_offsets.h")
            md_out = os.path.join(tmpdir, "test_summary.md")

            cmd = [
                "python", ANALYZER_SCRIPT,
                "--data-dir", DATA_DIR,
                "--json", json_out,
                "--header", header_out,
                "--markdown", md_out
            ]
            res = subprocess.run(cmd, cwd=WORKSPACE_ROOT, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"durak_analyzer.py failed:\n{res.stderr}")
            self.assertTrue(os.path.isfile(header_out), "C header was not generated")
            self.assertTrue(os.path.isfile(json_out), "JSON report was not generated")
            self.assertTrue(os.path.isfile(md_out), "Markdown summary was not generated")

            with open(json_out, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertEqual(data["status"], "SUCCESS")
            self.assertTrue(data["integrity_verified"])

            findings = data["findings"]
            self.assertEqual(findings["unity_natives"]["total_methods"], 71)
            self.assertEqual(len(findings["unity_natives"]["tables"]), 14)
            self.assertEqual(findings["memory_region_patches"]["count"], 18)
            self.assertEqual(len(findings["il2cpp_metadata_methods"]["playerprefs_methods"]), 17)
            self.assertTrue(findings["il2cpp_metadata_methods"]["evidence"]["abi_get_touch"]["verified_in_disassembly"])
            self.assertEqual(findings["timemanager_clock"]["entry_rva"], "0xbbf058")

    # --------------------------------------------------------------------------
    # 3. Missing Binary & Build ID Mutation Tests
    # --------------------------------------------------------------------------
    def test_04_fail_closed_on_missing_binary(self):
        """Verify analyzer fails closed if a required binary is missing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_data = self._setup_mock_data(tmpdir)
            os.remove(os.path.join(mock_data, "libunity.so"))

            header_out = os.path.join(tmpdir, "test_offsets.h")
            with open(header_out, "w") as f: f.write("// stale")

            cmd = ["python", ANALYZER_SCRIPT, "--data-dir", mock_data, "--header", header_out]
            res = subprocess.run(cmd, cwd=WORKSPACE_ROOT, capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertFalse(os.path.isfile(header_out))
            self.assertIn("ANALYSIS FAILED CLOSED", res.stderr)

    def test_05_fail_closed_on_corrupt_build_id(self):
        """Verify analyzer fails closed if ELF build-id does not match target manifest."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_data = self._setup_mock_data(tmpdir)
            unity_path = os.path.join(mock_data, "libunity.so")
            with open(unity_path, "r+b") as f:
                content = f.read()
                bid_bytes = bytes.fromhex("bcc661ea2046416d")
                idx = content.find(bid_bytes)
                self.assertNotEqual(idx, -1)
                f.seek(idx)
                f.write(b"\x00" * len(bid_bytes))

            # In test mode, build-id check directly raises RuntimeError
            analyzer = DurakFailClosedAnalyzer(mock_data, test_mode=True)
            with self.assertRaises(RuntimeError) as ctx:
                analyzer.run_all()
            self.assertIn("Build ID mismatch for libunity.so", str(ctx.exception))

            # In CLI mode, it strictly fails closed with non-zero exit code
            header_out = os.path.join(tmpdir, "test_offsets.h")
            with open(header_out, "w") as f: f.write("// stale")
            cmd = ["python", ANALYZER_SCRIPT, "--data-dir", mock_data, "--header", header_out]
            res = subprocess.run(cmd, cwd=WORKSPACE_ROOT, capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertFalse(os.path.isfile(header_out))

    def test_06_fail_closed_on_corrupt_metadata(self):
        """Verify analyzer fails closed if global-metadata.dat magic or version is invalid."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_data = self._setup_mock_data(tmpdir)
            meta_path = os.path.join(mock_data, "global-metadata.dat")
            with open(meta_path, "r+b") as f:
                f.seek(0)
                f.write(b"\x00\x00\x00\x00")

            header_out = os.path.join(tmpdir, "test_offsets.h")
            with open(header_out, "w") as f: f.write("// stale")

            cmd = ["python", ANALYZER_SCRIPT, "--data-dir", mock_data, "--header", header_out]
            res = subprocess.run(cmd, cwd=WORKSPACE_ROOT, capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertFalse(os.path.isfile(header_out))
            self.assertIn("ANALYSIS FAILED CLOSED", res.stderr)

    # --------------------------------------------------------------------------
    # 4. Binary SHA-256 Mutation (Finding 1 Gate)
    # --------------------------------------------------------------------------
    def test_07_fail_closed_on_binary_sha256_mutation(self):
        """Verify analyzer fails closed if 1 byte is modified in libmain.so without altering build-id."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_data = self._setup_mock_data(tmpdir)
            main_path = os.path.join(mock_data, "libmain.so")
            with open(main_path, "r+b") as f:
                f.seek(0x100)
                orig = f.read(1)
                f.seek(0x100)
                f.write(bytes([orig[0] ^ 0xFF]))

            header_out = os.path.join(tmpdir, "test_offsets.h")
            with open(header_out, "w") as f: f.write("// stale")

            cmd = ["python", ANALYZER_SCRIPT, "--data-dir", mock_data, "--header", header_out]
            res = subprocess.run(cmd, cwd=WORKSPACE_ROOT, capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertFalse(os.path.isfile(header_out))
            self.assertIn("SHA-256 mismatch for libmain.so", res.stderr)

    def test_08_cli_cannot_bypass_fail_closed(self):
        """Verify that CLI does not expose any flag to bypass SHA verification (Finding 1)."""
        cmd = ["python", ANALYZER_SCRIPT, "--skip-sha-check"]
        res = subprocess.run(cmd, cwd=WORKSPACE_ROOT, capture_output=True, text=True)
        self.assertEqual(res.returncode, 2, "CLI must reject removed --skip-sha-check flag")
        self.assertIn("unrecognized arguments", res.stderr)

    def test_09_artifact_generation_fails_on_unverified(self):
        """Verify generate_c_header and generate_markdown_summary fail-closed on unverified runs (Finding 1)."""
        unverified_results = {
            "status": "TEST_ONLY_UNVERIFIED",
            "integrity_verified": False,
            "findings": {}
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            dummy_header = os.path.join(tmpdir, "header.h")
            dummy_md = os.path.join(tmpdir, "summary.md")

            with self.assertRaises(RuntimeError) as ctx:
                generate_c_header(unverified_results, dummy_header)
            self.assertIn("Cannot generate production C header", str(ctx.exception))

            with self.assertRaises(RuntimeError) as ctx:
                generate_markdown_summary(unverified_results, dummy_md)
            self.assertIn("Cannot generate production markdown report", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 5. TimeManager::Update Instruction Mutation
    # --------------------------------------------------------------------------
    def test_10_fail_closed_on_timemanager_mutation(self):
        """Verify analyzer fails closed if 4th instruction of TimeManager::Update is modified."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_data = self._setup_mock_data(tmpdir)
            unity_path = os.path.join(mock_data, "libunity.so")

            # Mutate TimeManager::Update 4th instruction at 0xBBF064 (file offset 0xbbb064)
            with open(unity_path, "r+b") as f:
                f.seek(0xbbb064)
                w = struct.unpack('<I', f.read(4))[0]
                self.assertEqual(w, 0x91000508)
                f.seek(0xbbb064)
                f.write(struct.pack('<I', 0xD503201F))  # NOP

            analyzer = DurakFailClosedAnalyzer(mock_data, test_mode=True)
            with self.assertRaises(RuntimeError) as ctx:
                analyzer.run_all()
            self.assertIn("TimeManager::Update matching must yield exactly 1 candidate", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 6. Allocator 18-Site Chain Mutation
    # --------------------------------------------------------------------------
    def test_11_fail_closed_on_allocator_mutation(self):
        """Verify analyzer fails closed if an instruction in the allocator chain is corrupted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_data = self._setup_mock_data(tmpdir)
            unity_path = os.path.join(mock_data, "libunity.so")

            # Mutate Site 1 word at 0xFA116C (file offset 0xf9d16c)
            with open(unity_path, "r+b") as f:
                f.seek(0xf9d16c)
                w = struct.unpack('<I', f.read(4))[0]
                self.assertEqual(w, 0x12be0009)
                f.seek(0xf9d16c)
                f.write(struct.pack('<I', 0xD503201F))  # NOP

            analyzer = DurakFailClosedAnalyzer(mock_data, test_mode=True)
            with self.assertRaises(RuntimeError) as ctx:
                analyzer.run_all()
            self.assertIn("Allocator Site 1 fingerprint not found anywhere in .text", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 7. IL2CPP JNI Globals Pattern Mutation
    # --------------------------------------------------------------------------
    def test_12_fail_closed_on_jni_globals_mutation(self):
        """Verify analyzer fails closed if JNI_OnLoad JavaVM store pattern in libil2cpp is corrupted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_data = self._setup_mock_data(tmpdir)
            il2cpp_path = os.path.join(mock_data, "libil2cpp.so")

            with open(il2cpp_path, "r+b") as f:
                content = f.read()
                store_bytes = struct.pack('<I', 0xf9007d13)
                idx = content.find(store_bytes)
                self.assertNotEqual(idx, -1)
                f.seek(idx)
                f.write(struct.pack('<I', 0xD503201F))  # NOP

            analyzer = DurakFailClosedAnalyzer(mock_data, test_mode=True)
            with self.assertRaises(RuntimeError) as ctx:
                analyzer.run_all()
            self.assertIn("Failed to resolve JNI_OnLoad globals pattern in libil2cpp.so", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 8. RegisterNatives Table Corruption
    # --------------------------------------------------------------------------
    def test_13_fail_closed_on_registernatives_corruption(self):
        """Verify analyzer fails closed if a RegisterNatives table is corrupted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_data = self._setup_mock_data(tmpdir)
            unity_path = os.path.join(mock_data, "libunity.so")

            # Corrupt the string "nativeRender" in libunity.so
            with open(unity_path, "r+b") as f:
                content = f.read()
                nr_bytes = b"nativeRender\0"
                idx = content.find(nr_bytes)
                self.assertNotEqual(idx, -1)
                f.seek(idx)
                f.write(b"\x00" * len(nr_bytes))

            analyzer = DurakFailClosedAnalyzer(mock_data, test_mode=True)
            with self.assertRaises(RuntimeError) as ctx:
                analyzer.run_all()
            self.assertTrue("Invalid" in str(ctx.exception) or "RegisterNatives" in str(ctx.exception))

    # --------------------------------------------------------------------------
    # 9. Method Pointer Relocation to NULL
    # --------------------------------------------------------------------------
    def test_14_fail_closed_on_null_method_pointer_relocation(self):
        """Verify analyzer fails closed if an IL2CPP method pointer relocation is NULL."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_data = self._setup_mock_data(tmpdir)
            il2cpp_path = os.path.join(mock_data, "libil2cpp.so")

            # Mutate relocation for PlayerPrefs::GetInt1 (RVA 0x17eedb0)
            target_rva = 0x17eedb0
            with open(il2cpp_path, "r+b") as f:
                content = f.read()
                rva_bytes = struct.pack('<Q', target_rva)
                idx = content.find(rva_bytes)
                self.assertNotEqual(idx, -1)
                f.seek(idx)
                f.write(b"\x00" * 8)  # Set addend to NULL

            analyzer = DurakFailClosedAnalyzer(mock_data, test_mode=True)
            with self.assertRaises(RuntimeError) as ctx:
                analyzer.run_all()
            self.assertIn("NULL", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 10. Touch ABI Struct Size & Memcpy Call Mutation (Finding 2)
    # --------------------------------------------------------------------------
    def test_15_fail_closed_on_touch_abi_struct_size_mutation(self):
        """Verify analyzer fails closed if GetTouch struct size instruction is mutated from 0x44."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_data = self._setup_mock_data(tmpdir)
            il2cpp_path = os.path.join(mock_data, "libil2cpp.so")

            # In GetTouch (0x1843998), instruction 0x18439f0 is mov w2, #0x44 (0x52800882)
            # Its exact file offset in libil2cpp.so is 0x183f9f0
            with open(il2cpp_path, "r+b") as f:
                f.seek(0x183f9f0)
                orig_ins = struct.unpack('<I', f.read(4))[0]
                self.assertEqual(orig_ins, 0x52800882, "Instruction at 0x183f9f0 must be mov w2, #0x44")
                f.seek(0x183f9f0)
                f.write(struct.pack('<I', 0x52800802))  # Change to mov w2, #0x40

            analyzer = DurakFailClosedAnalyzer(mock_data, test_mode=True)
            with self.assertRaises(RuntimeError) as ctx:
                analyzer.run_all()
            self.assertIn("Touch ABI", str(ctx.exception))

    def test_16_fail_closed_on_touch_abi_memcpy_call_mutation(self):
        """Verify analyzer fails closed if GetTouch bl memcpy call is mutated (Finding 2)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_data = self._setup_mock_data(tmpdir)
            il2cpp_path = os.path.join(mock_data, "libil2cpp.so")

            # In GetTouch (0x1843998), instruction 0x18439f4 is bl memcpy (0x940ac94f)
            # Its exact file offset in libil2cpp.so is 0x183f9f4
            with open(il2cpp_path, "r+b") as f:
                f.seek(0x183f9f4)
                orig_ins = struct.unpack('<I', f.read(4))[0]
                self.assertEqual(orig_ins, 0x940ac94f, "Instruction at 0x183f9f4 must be bl memcpy")
                f.seek(0x183f9f4)
                f.write(struct.pack('<I', 0xD503201F))  # Mutate to NOP

            analyzer = DurakFailClosedAnalyzer(mock_data, test_mode=True)
            with self.assertRaises(RuntimeError) as ctx:
                analyzer.run_all()
            self.assertIn("Touch ABI verification failed in disassembly", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 11. PlayerPrefs Parameter Type Mutation (Finding 3)
    # --------------------------------------------------------------------------
    def test_17_fail_closed_on_playerprefs_parameter_type_mutation(self):
        """Verify analyzer fails closed if PlayerPrefs.GetInt defaultValue param type is mutated (Finding 3)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_data = self._setup_mock_data(tmpdir)
            meta_path = os.path.join(mock_data, "global-metadata.dat")

            # In global-metadata.dat, defaultValue param definition of GetInt(key, defaultValue)
            # is at file offset 0x499a7e. type_index is at 0x499a86.
            with open(meta_path, "r+b") as f:
                f.seek(0x499a86)
                orig_type = struct.unpack('<H', f.read(2))[0]
                self.assertEqual(orig_type, 15979, "type_index of defaultValue must be 15979 (System.Int32)")
                f.seek(0x499a86)
                f.write(struct.pack('<H', 19805))  # Mutate to 19805 (System.String)

            analyzer = DurakFailClosedAnalyzer(mock_data, test_mode=True)
            with self.assertRaises(RuntimeError) as ctx:
                analyzer.run_all()
            self.assertIn("Unexpected signature for PlayerPrefs::GetInt", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 12. RegisterNatives Java Class Attribution (Finding 4)
    # --------------------------------------------------------------------------
    def test_18_registernatives_class_attribution_and_call_sites(self):
        """Verify that all 69 RegisterNatives methods are attributed to their Java classes (Finding 4)."""
        analyzer = DurakFailClosedAnalyzer(DATA_DIR, test_mode=False)
        results = analyzer.run_all()

        findings = results["findings"]["unity_natives"]
        self.assertEqual(findings["total_methods"], 71)
        self.assertEqual(len(findings["tables"]), 14)

        # Check all tables
        for table in findings["tables"]:
            self.assertTrue(table["registered_class"], f"Table {table['table_vaddr']} missing registered_class")
            self.assertNotEqual(table["registered_class"], "Unknown", f"Table {table['table_vaddr']} has Unknown class")
            self.assertTrue(table["registration_call_site"], f"Table {table['table_vaddr']} missing registration_call_site")

        # Check lifecycle entry points
        lc = findings["lifecycle_entrypoints"]
        for name, info in lc.items():
            if name in ('JNI_OnLoad', 'JNI_OnUnload'):
                self.assertEqual(info["confidence"], "CONFIRMED_EXPORT")
                continue
            self.assertTrue(info.get("registered_class"), f"Method {name} missing registered_class")
            self.assertNotEqual(info.get("registered_class"), "Unknown", f"Method {name} has Unknown class")
            self.assertTrue(info.get("registration_call_site"), f"Method {name} missing registration_call_site")

        # Specific class checks
        self.assertEqual(lc["initJni"]["registered_class"], "com/unity3d/player/UnityPlayer")
        self.assertEqual(lc["nativeRender"]["registered_class"], "com/unity3d/player/UnityPlayerForActivityOrService")
        self.assertEqual(lc["nativePause"]["registered_class"], "com/unity3d/player/UnityPlayerForActivityOrService")
        self.assertEqual(lc["nativeResume"]["registered_class"], "com/unity3d/player/UnityPlayerForActivityOrService")

        # Check recovered singleton tables
        self.assertEqual(lc["nativeUpdateOrientationLockState"]["registered_class"], "com/unity3d/player/OrientationLockListener")
        self.assertEqual(lc["nativeGetSoftInputType"]["registered_class"], "com/unity3d/player/SoftInputProvider")
        self.assertEqual(lc["nativeProxyInvoke"]["registered_class"], "com/unity3d/player/ReflectionHelper")

        # FMOD audio methods
        fmod = findings["fmod_natives"]
        for name, info in fmod.items():
            self.assertEqual(info["registered_class"], "org/fmod/FMODAudioDevice")

    # --------------------------------------------------------------------------
    # 13. RegisterNatives Dispatch Mutation Fail-Closed Gate (Finding 3)
    # --------------------------------------------------------------------------
    def test_19_fail_closed_on_registernatives_dispatch_mutation(self):
        """Verify analyzer fails closed if a RegisterNatives dispatch instruction is mutated to NOP."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_data = self._setup_mock_data(tmpdir)
            unity_path = os.path.join(mock_data, "libunity.so")

            # Mutate FMOD RegisterNatives dispatch instruction at file offset 0x108a8c4
            # (RVA 0x108e8c4: ldr x8, [x8, #0x6b8] == 0xf9435d08) to NOP
            with open(unity_path, "r+b") as f:
                f.seek(0x108a8c4)
                w = struct.unpack('<I', f.read(4))[0]
                self.assertEqual(w, 0xf9435d08, "Instruction at 0x108a8c4 must be ldr x8, [x8, #0x6b8]")
                f.seek(0x108a8c4)
                f.write(struct.pack('<I', 0xd503201f))  # NOP

            analyzer = DurakFailClosedAnalyzer(mock_data, test_mode=True)
            with self.assertRaises(RuntimeError) as ctx:
                analyzer.run_all()
            self.assertIn("Expected exactly 14 RegisterNatives call sites, found 13", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
