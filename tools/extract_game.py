#!/usr/bin/env python3
"""
extract_game.py - Game Asset and Core Native Library Extractor for Durak NX (ru.appscraft.durak)

Extracts and verifies (FAIL-CLOSED):
  - Target APKS SHA-256
  - AndroidManifest.xml: package, versionName, versionCode
  - Core native libraries: libmain.so, libunity.so, libil2cpp.so, libsqlite3.so
  - ELF header validation: ELF64, AArch64, Little Endian, Build ID, SHA-256
  - Unity data files: assets/bin/Data/...
  - Builds reproducible game_manifest.json and SD card directory layout
"""

import os
import sys
import io
import json
import struct
import hashlib
import zipfile
import argparse
from typing import Dict, Any, List, Optional
from elftools.elf.elffile import ELFFile

EXPECTED_APKS_SHA256 = "91e51b321ae26382a273534225165f229f41c13831e9d16b164de3679a74a615"
EXPECTED_PACKAGE = "ru.appscraft.durak"
EXPECTED_VERSION_NAME = "25.0"
EXPECTED_VERSION_CODE = 250

EXPECTED_CORE_LIBRARIES = {
    "libmain.so": {
        "rel_path": "lib/arm64-v8a/libmain.so",
        "size": 6696,
        "sha256": "c11373dffa1bab427e8864a40313111de2a70367d052d87f33a9069ce8949d93",
        "build_id": "c5498ab8c791f1473a54c79a9d3c5b738ff6d941"
    },
    "libunity.so": {
        "rel_path": "lib/arm64-v8a/libunity.so",
        "size": 21388304,
        "sha256": "292f89210151ba0060f77d137cd6a00a52158dc5da760d4bf106158fc9309cef",
        "build_id": "bcc661ea2046416d"
    },
    "libil2cpp.so": {
        "rel_path": "lib/arm64-v8a/libil2cpp.so",
        "size": 31256704,
        "sha256": "7bc9c2e7e20c741a511e6645589db16d0fa084d79bcfc12ba1fab78931e2271c",
        "build_id": "d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0"
    },
    "libsqlite3.so": {
        "rel_path": "lib/arm64-v8a/libsqlite3.so",
        "size": 1797248,
        "sha256": "6df7a75d31c417cae7e877fd7c3d190e0ac47b1f104ae0ae5501d72491b1c32c",
        "build_id": "99495662cefa74605573c8dc36a53cb1f842764d"
    }
}

EXPECTED_METADATA_SHA256 = "1e31859eca996941dbdeb3ab9df208f4359422440110607494e74cc8cafc5b6a"
EXPECTED_METADATA_SIZE = 7639464


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def parse_axml_manifest(axml_data: bytes) -> Dict[str, Any]:
    """Parse Android binary XML to extract <manifest> tag attributes."""
    if len(axml_data) < 36:
        raise ValueError("AXML data too small to be valid Android binary XML")
    sp_type, _, sp_size = struct.unpack('<HHI', axml_data[8:16])
    if sp_type != 0x0001:
        raise ValueError(f"Invalid AXML string pool type: {sp_type:#x}")
    str_count, _, flags, str_start, _ = struct.unpack('<5I', axml_data[16:36])
    is_utf8 = bool(flags & (1 << 8))
    offsets = struct.unpack(f'<{str_count}I', axml_data[36:36 + str_count * 4])
    base_str = 8 + str_start
    strings = []
    for off in offsets:
        pos = base_str + off
        if pos >= len(axml_data):
            strings.append('')
            continue
        if is_utf8:
            l1 = axml_data[pos]; pos += 2 if (l1 & 0x80) else 1
            u8_len = axml_data[pos]; pos += 2 if (u8_len & 0x80) else 1
            s = axml_data[pos: pos + u8_len].decode('utf-8', errors='replace')
        else:
            u16_len = struct.unpack('<H', axml_data[pos:pos + 2])[0]
            s = axml_data[pos + 2: pos + 2 + u16_len * 2].decode('utf-16le', errors='replace')
        strings.append(s)

    pos = 8 + sp_size
    chunk_type, _, chunk_size = struct.unpack('<HHI', axml_data[pos:pos + 8])
    if chunk_type == 0x0180:  # Resource ID chunk
        pos += chunk_size

    manifest_info: Dict[str, Any] = {}
    while pos < len(axml_data):
        chunk_type, header_size, chunk_size = struct.unpack('<HHI', axml_data[pos:pos + 8])
        if chunk_type == 0x0102:  # START_TAG
            ns_idx, name_idx = struct.unpack('<II', axml_data[pos + 16:pos + 24])
            tag = strings[name_idx] if name_idx < len(strings) else ''
            if tag == 'manifest':
                attr_start, attr_size, attr_count = struct.unpack('<HHH', axml_data[pos + 24:pos + 30])
                attr_base = pos + 16 + attr_start
                for i in range(attr_count):
                    a_raw = axml_data[attr_base + i * attr_size: attr_base + (i + 1) * attr_size]
                    a_ns, a_name, a_val_str, a_size, a_res0, a_type, a_data = struct.unpack('<IIIHBBI', a_raw)
                    attr_name = strings[a_name] if a_name < len(strings) else ''
                    val_str = strings[a_val_str] if (a_val_str != 0xFFFFFFFF and a_val_str < len(strings)) else ''
                    if attr_name == 'package':
                        manifest_info['package'] = val_str
                    elif attr_name == 'versionName':
                        manifest_info['versionName'] = val_str
                    elif attr_name == 'versionCode':
                        manifest_info['versionCode'] = a_data
                break
        pos += chunk_size

    return manifest_info


def get_elf_build_id(elf_data: bytes) -> Optional[str]:
    """Extract GNU build ID from an ELF binary."""
    try:
        elf = ELFFile(io.BytesIO(elf_data))
        for s in elf.iter_sections():
            if s.name == '.note.gnu.build-id':
                for note in s.iter_notes():
                    if 'n_desc' in note:
                        return note['n_desc']
                    elif hasattr(note, 'desc'):
                        return note.desc
    except Exception:
        pass
    return None


def extract_game(apks_path: str, out_dir: str, verify_only: bool = False) -> Dict[str, Any]:
    print(f"[*] Opening APKS bundle: {apks_path}")
    if not os.path.isfile(apks_path):
        raise FileNotFoundError(f"APKS file not found: {apks_path}")

    # 1. Fail-closed APKS SHA-256 verification
    apks_sha256 = sha256_file(apks_path)
    print(f"    -> APKS SHA-256: {apks_sha256}")
    if apks_sha256 != EXPECTED_APKS_SHA256:
        raise ValueError(f"APKS SHA-256 mismatch! Got '{apks_sha256}', expected '{EXPECTED_APKS_SHA256}'")

    manifest: Dict[str, Any] = {
        "apks": {
            "path": os.path.abspath(apks_path),
            "size": os.path.getsize(apks_path),
            "sha256": apks_sha256
        },
        "package_info": {},
        "unity_info": {},
        "core_libraries": {},
        "assets": {},
        "target_sd_layout": {}
    }

    with zipfile.ZipFile(apks_path, 'r') as apks:
        namelist = apks.namelist()
        if 'base.apk' not in namelist or 'split_config.arm64_v8a.apk' not in namelist:
            raise ValueError("APKS does not contain expected base.apk and split_config.arm64_v8a.apk")

        base_data = apks.read('base.apk')
        arm_data = apks.read('split_config.arm64_v8a.apk')

        manifest["apks"]["base_apk_sha256"] = sha256_bytes(base_data)
        manifest["apks"]["arm64_apk_sha256"] = sha256_bytes(arm_data)

        # 2. Strict Manifest Verification
        with zipfile.ZipFile(io.BytesIO(base_data)) as base_apk:
            manifest_xml = base_apk.read('AndroidManifest.xml')
            info = parse_axml_manifest(manifest_xml)

            actual_pkg = info.get('package', '')
            actual_ver_name = info.get('versionName', '')
            actual_ver_code = info.get('versionCode', 0)

            if actual_pkg != EXPECTED_PACKAGE:
                raise ValueError(f"Package mismatch: have '{actual_pkg}', expected '{EXPECTED_PACKAGE}'")
            if actual_ver_name != EXPECTED_VERSION_NAME:
                raise ValueError(f"VersionName mismatch: have '{actual_ver_name}', expected '{EXPECTED_VERSION_NAME}'")
            if actual_ver_code != EXPECTED_VERSION_CODE:
                raise ValueError(f"VersionCode mismatch: have {actual_ver_code}, expected {EXPECTED_VERSION_CODE}")

            manifest["package_info"] = {
                "package_name": actual_pkg,
                "version_name": actual_ver_name,
                "version_code": actual_ver_code,
                "verified": True
            }
            print(f"    -> Package: {actual_pkg}, Version: {actual_ver_name} (code {actual_ver_code}) [VERIFIED]")

            # Unity fingerprint
            if 'META-INF/com.android.games.engine.build_fingerprint' in base_apk.namelist():
                fp = base_apk.read('META-INF/com.android.games.engine.build_fingerprint').decode('utf-8').strip()
                manifest["unity_info"]["build_fingerprint"] = fp
                print(f"    -> Engine fingerprint: {fp}")

            if 'assets/bin/Data/boot.config' in base_apk.namelist():
                boot_cfg = base_apk.read('assets/bin/Data/boot.config').decode('utf-8', errors='replace')
                manifest["unity_info"]["boot_config"] = boot_cfg.strip().splitlines()

        # 3. Inspect, Parse & Verify Core ELF Libraries
        with zipfile.ZipFile(io.BytesIO(arm_data)) as arm_apk:
            for fn, exp in EXPECTED_CORE_LIBRARIES.items():
                lib_path = exp["rel_path"]
                if lib_path not in arm_apk.namelist():
                    raise ValueError(f"Required library missing from arm64 split: {lib_path}")

                data = arm_apk.read(lib_path)
                h = sha256_bytes(data)
                bid = get_elf_build_id(data)
                sz = len(data)

                if h != exp["sha256"]:
                    raise ValueError(f"SHA-256 mismatch for {fn}: have {h}, expected {exp['sha256']}")
                if bid != exp["build_id"]:
                    raise ValueError(f"Build ID mismatch for {fn}: have {bid}, expected {exp['build_id']}")
                if sz != exp["size"]:
                    raise ValueError(f"Size mismatch for {fn}: have {sz}, expected {exp['size']}")

                # Directly verify ELF header fields
                elf = ELFFile(io.BytesIO(data))
                e_ident = elf.header['e_ident']
                elf_class = e_ident['EI_CLASS']
                elf_data = e_ident['EI_DATA']
                machine = elf.header['e_machine']

                if elf_class != 'ELFCLASS64':
                    raise ValueError(f"Invalid ELF class for {fn}: {elf_class} (expected ELFCLASS64)")
                if elf_data != 'ELFDATA2LSB':
                    raise ValueError(f"Invalid ELF endianness for {fn}: {elf_data} (expected ELFDATA2LSB)")
                if machine != 'EM_AARCH64':
                    raise ValueError(f"Invalid ELF machine architecture for {fn}: {machine} (expected EM_AARCH64)")

                manifest["core_libraries"][fn] = {
                    "size": sz,
                    "sha256": h,
                    "build_id": bid,
                    "elf_class": elf_class,
                    "machine": machine,
                    "verified": True
                }
                print(f"    -> Core library: {fn:<15} size={sz:8d} build-id={bid} [VERIFIED]")

        # 4. Inspect Unity Data Files and verify global-metadata.dat
        with zipfile.ZipFile(io.BytesIO(base_data)) as base_apk:
            data_files = [n for n in base_apk.namelist() if n.startswith('assets/bin/Data')]
            has_meta = False
            for af in sorted(data_files):
                data = base_apk.read(af)
                rel_path = af[len('assets/bin/Data/'):]
                h = sha256_bytes(data)
                manifest["assets"][rel_path] = {
                    "size": len(data),
                    "sha256": h
                }
                if rel_path.endswith('global-metadata.dat'):
                    has_meta = True
                    if h != EXPECTED_METADATA_SHA256:
                        raise ValueError(f"global-metadata.dat SHA-256 mismatch: have {h}, expected {EXPECTED_METADATA_SHA256}")
                    if len(data) != EXPECTED_METADATA_SIZE:
                        raise ValueError(f"global-metadata.dat size mismatch: have {len(data)}, expected {EXPECTED_METADATA_SIZE}")
                    # Verify magic and version
                    magic, ver = struct.unpack('<II', data[:8])
                    if magic != 0xFAB11BAF or ver != 39:
                        raise ValueError(f"Invalid metadata magic {magic:#x} or version {ver} (expected 0xfab11baf / 39)")

            if not has_meta:
                raise ValueError("global-metadata.dat missing from base.apk assets")

    if verify_only:
        print("[+] Verification complete (verify_only mode, all targets strictly verified).")
        return manifest

    # 5. Extraction into SD layout
    game_dir = os.path.join(out_dir, "sdmc", "switch", "durak_nx", "game")
    save_dir = os.path.join(out_dir, "sdmc", "switch", "durak_nx", "save")
    lib_dir = os.path.join(game_dir, "lib")
    data_dest_dir = os.path.join(game_dir, "assets", "bin", "Data")

    os.makedirs(lib_dir, exist_ok=True)
    os.makedirs(save_dir, exist_ok=True)
    os.makedirs(data_dest_dir, exist_ok=True)

    # Core libraries
    for fn in ("libunity.so", "libil2cpp.so", "libmain.so", "libsqlite3.so"):
        with zipfile.ZipFile(apks_path, 'r') as apks:
            with zipfile.ZipFile(io.BytesIO(apks.read('split_config.arm64_v8a.apk'))) as arm_apk:
                data = arm_apk.read(f"lib/arm64-v8a/{fn}")
                with open(os.path.join(lib_dir, fn), 'wb') as f:
                    f.write(data)
                with open(os.path.join(out_dir, fn), 'wb') as f:
                    f.write(data)

    # Assets
    with zipfile.ZipFile(apks_path, 'r') as apks:
        with zipfile.ZipFile(io.BytesIO(apks.read('base.apk'))) as base_apk:
            for af in data_files:
                data = base_apk.read(af)
                rel_path = af[len('assets/bin/Data/'):]
                target_path = os.path.join(data_dest_dir, rel_path)
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with open(target_path, 'wb') as f:
                    f.write(data)
                if rel_path.endswith('global-metadata.dat'):
                    with open(os.path.join(out_dir, 'global-metadata.dat'), 'wb') as f:
                        f.write(data)

    manifest["target_sd_layout"] = {
        "game_directory": "sdmc:/switch/durak_nx/game/",
        "save_directory": "sdmc:/switch/durak_nx/save/",
        "libraries_path": "sdmc:/switch/durak_nx/game/lib/",
        "assets_path": "sdmc:/switch/durak_nx/game/assets/bin/Data/"
    }

    manifest_path = os.path.join(out_dir, "game_manifest.json")
    with open(manifest_path, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2)
    print(f"[+] Extraction complete. Manifest saved to: {manifest_path}")

    return manifest


def main():
    parser = argparse.ArgumentParser(description="Durak 25.0 Game Asset & Native Extractor")
    parser.add_argument("--apks", default="Durak_25.0.apks", help="Path to Durak_25.0.apks")
    parser.add_argument("--out", default="extracted_durak", help="Output directory for extracted game layout")
    parser.add_argument("--verify-only", action="store_true", help="Only verify hashes and manifest without writing")
    args = parser.parse_args()

    try:
        extract_game(args.apks, args.out, args.verify_only)
    except Exception as e:
        print(f"[!] Extraction failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
