"""Read-only evidence for Durak 25.0 inventory grants and stock patch."""
import io
import re
import sqlite3
import struct
import sys
from pathlib import Path
import UnityPy
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'tools'))
from metadata_v39 import Il2CppMetadataV39

meta = Il2CppMetadataV39((root / 'extracted_durak/global-metadata.dat').read_bytes())
raw = (root / 'extracted_durak/libil2cpp.so').read_bytes()
elf = ELFFile(io.BytesIO(raw))
rels = {r['r_offset']: r['r_addend'] for r in elf.get_section_by_name('.rela.dyn').iter_relocations()}
ro = elf.get_section_by_name('.rodata')
name = ro['sh_addr'] + ro.data().index(b'Assembly-CSharp.dll\0')
modules = [k for k,v in rels.items() if v == name]
assert len(modules) == 1
module = modules[0]

def read(va, size):
    for seg in elf.iter_segments():
        if seg['p_type'] == 'PT_LOAD' and seg['p_vaddr'] <= va and va + size <= seg['p_vaddr'] + seg['p_filesz']:
            offset = seg['p_offset'] + va - seg['p_vaddr']
            return raw[offset:offset+size]
    raise ValueError(f'Unmapped target RVA {va:#x}')

count = struct.unpack('<I', read(module+8,4))[0]
pointers = rels[module+16]
image = next(i for i in meta.get_images() if i['name'] == 'Assembly-CSharp.dll')
types = meta.get_type_definitions()[image['type_start']:image['type_start']+image['type_count']]

def method(namespace, cls, name):
    typ = next(t for t in types if t['namespace'] == namespace and t['name'] == cls)
    result = next(m for m in meta.get_methods_for_type(typ) if m['name'] == name)
    assert 1 <= result['rid'] <= count
    return result, rels[pointers + (result['rid']-1)*8]

use, start = method('', 'GadgetSelectWindow', 'useGadget')
assert use['token'] == 0x06000416 and use['param_count'] == 0 and start == 0xd67434
_, end = method('', 'GadgetSelectWindow', 'Start')
header = (root / 'include/region_patch.h').read_text()
site = int(re.search(r'#define DURAK_GADGET_STOCK_RVA (0x[0-9a-f]+)',header)[1],16)
words = header.split('DURAK_GADGET_STOCK_CONTEXT[] = {')[1].split('};')[0]
expected = struct.pack('<12I', *[int(x,16) for x in re.findall(r'0x[0-9a-f]+', words)])
assert start < site and site+len(expected) < end and read(site,len(expected)) == expected
cs = Cs(CS_ARCH_ARM64,CS_MODE_ARM)
instructions = list(cs.disasm(expected,site))
assert instructions[4].op_str == 'w9, [x1, #0x1c]'
assert instructions[5].mnemonic == 'subs' and instructions[5].op_str == 'w9, w9, #1'
assert instructions[6].mnemonic == 'b.lt'
assert instructions[7].op_str == 'w9, [x1, #0x1c]'
patched = next(cs.disasm(struct.pack('<I',0x71000129),site+20))
assert patched.mnemonic == 'subs' and patched.op_str == 'w9, w9, #0'
_, effect = method('', 'GameManager', 'UseGadget')
calls = [(i.address, int(i.op_str[1:],0)) for i in cs.disasm(read(start,end-start),start)
         if i.mnemonic == 'bl' and i.op_str.startswith('#')]
assert (0xd67720,effect) in calls and effect == 0xd10f88
quantity, getter = method('MetricsTypes','gadgets','get_number')
decoded = list(cs.disasm(read(getter,8),getter))
assert quantity['param_count'] == 0 and decoded[0].op_str == 'w0, [x0, #0x1c]' and decoded[1].mnemonic == 'ret'
print(f'[PASS] GadgetSelectWindow.useGadget token={use["token"]:#x} start={start:#x}: stock patch {site+20:#x}; number getter {getter:#x}; effect call retained')

env = UnityPy.load(str(root / 'extracted_durak/sdmc/switch/durak_nx/game/assets/bin/Data/data.unity3d'))
sprites = {o.read().m_Name for o in env.objects if o.type.name == 'Sprite'}
dictionary = next(o.read() for o in env.objects if o.type.name == 'TextAsset' and o.read().m_Name == 'dict')
db_bytes = dictionary.m_Script
if isinstance(db_bytes,str):
    db_bytes = db_bytes.encode('utf8',errors='surrogateescape')
db = sqlite3.connect(':memory:')
db.deserialize(db_bytes)
source = (root / 'source/cosmetics_inventory.c').read_text()
for table,column,total in [('covers','dict_cover_id',8),('avatars','dict_avatar_id',39),('gadgets','dict_gadget_id',4)]:
    rows = db.execute(f'SELECT id,pic FROM "{table}" ORDER BY id').fetchall()
    assert [r[0] for r in rows] == list(range(1,total+1))
    assert all(str(pic) in sprites for _,pic in rows)
    assert f'{{"{table}","{column}",{total}}}' in source
    for prop in ['get_id','get_'+column] + (['get_number'] if table == 'gadgets' else []):
        method('MetricsTypes',table,prop)
    print(f'[PASS] {table}: {total} catalog IDs, {total} bundled sprites, MetricsTypes property contract')
db.close()
with (root / 'extracted_durak/libsqlite3.so').open('rb') as stream:
    symbols = ELFFile(stream).get_section_by_name('.dynsym')
    for api in ['prepare_v2','step','finalize','column_text','column_int','exec','extended_errcode','errmsg','db_filename']:
        assert symbols.get_symbol_by_name('sqlite3_'+api)
print('[PASS] All inventory SQLite API exports present in target library')
