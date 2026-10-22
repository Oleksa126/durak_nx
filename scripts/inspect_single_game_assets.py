"""Read-only serialized DB bindings; requires UnityPy (analysis only)."""
import argparse
import json
import sqlite3
import struct
import sys
from pathlib import Path
import UnityPy
from UnityPy.classes import PPtr
from elftools.elf.elffile import ELFFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from metadata_v39 import Il2CppMetadataV39

meta = Il2CppMetadataV39(Path('extracted_durak/global-metadata.dat').read_bytes())
with open('extracted_durak/libil2cpp.so', 'rb') as stream:
    elf = ELFFile(stream)
    rels = {r['r_offset']: r['r_addend'] for r in
            elf.get_section_by_name('.rela.dyn').iter_relocations()}
    ro = elf.get_section_by_name('.rodata')

    def read_va(va, size):
        for seg in elf.iter_segments():
            if seg['p_type'] == 'PT_LOAD' and seg['p_vaddr'] <= va and va + size <= seg['p_vaddr'] + seg['p_filesz']:
                stream.seek(seg['p_offset'] + va - seg['p_vaddr'])
                return stream.read(size)
        raise ValueError(f'Unmapped VA {va:x}')

    for image in meta.get_images():
        if image['name'] not in {'Assembly-CSharp.dll', 'SimpleSQL_Runtime.dll'}:
            continue
        position = ro.data().find(image['name'].encode() + b'\0')
        assert position >= 0
        name_va = ro['sh_addr'] + position
        cgm = next(address for address, value in rels.items() if value == name_va)
        # Il2CppCodeGenModule: name @0, count @8, methodPointers @16.
        count = struct.unpack_from('<I', read_va(cgm, 32), 8)[0]
        pointers = rels[cgm + 16]
        assert cgm and pointers and count
        print('CodeGenModule', image['name'], hex(cgm), hex(pointers), count)
        types = meta.get_type_definitions()[image['type_start']:image['type_start'] + image['type_count']]
        for typ in types:
            if typ['name'] == 'single_stats':
                print('table type:', typ['namespace'], typ['name'])
            if typ['name'] not in {'DataManager', 'SinglePlayerSelect', 'SimpleSQLManager'}:
                continue
            for method in meta.get_methods_for_type(typ):
                if method['name'] in {'Awake', 'Initialize', 'UpdateDatabaseStructure',
                                      'DetectTables', 'CreateTable', 'OnEnable', 'redrawGameList'}:
                    assert 1 <= method['rid'] <= count
                    print(typ['name'], method['name'], hex(rels.get(pointers + 8 * (method['rid'] - 1), 0)))

parser = argparse.ArgumentParser()
parser.add_argument('bundle', nargs='?', default=
                    'extracted_durak/sdmc/switch/durak_nx/assets/bin/Data/data.unity3d')
args = parser.parse_args()
env = UnityPy.load(args.bundle)
for obj in env.objects:
    if obj.type.name == 'MonoBehaviour':
        behaviour = obj.read(check_read=False)
        try:
            name = behaviour.m_Script.read().m_ClassName
        except (AttributeError, KeyError, ValueError):
            continue
        if name in {'SinglePlayerSelect', 'SimpleSQLManager', 'DataManager'}:
            print(name, obj.assets_file.name, obj.path_id)
            print(json.dumps(obj.read_typetree(check_read=False), ensure_ascii=True))
            raw = obj.get_raw_data()
            print('serialized prefix (96 bytes):', raw[:96].hex())
            if name == 'SimpleSQLManager':
                # _db is private/nonserialized; databaseFile is first saved field.
                file_id, path_id = struct.unpack_from('<iq', raw, 32)
                target = PPtr(m_FileID=file_id, m_PathID=path_id,
                              assetsfile=obj.assets_file).read()
                print('databaseFile:', target.m_Name)
            elif name == 'DataManager':
                length = struct.unpack_from('<I', raw, 32)[0]
                print('dataTypesNamespace:', raw[36:36+length].decode('ascii'))
    elif obj.type.name == 'TextAsset':
        asset = obj.read()
        if asset.m_Name == 'metrics':
            raw = asset.m_Script
            if isinstance(raw, str):
                raw = raw.encode('utf8', errors='surrogateescape')
            db = sqlite3.connect(':memory:')
            db.deserialize(raw)
            print('metrics asset schema:', db.execute(
                'SELECT name, sql FROM sqlite_master ORDER BY name').fetchall())
            db.close()
