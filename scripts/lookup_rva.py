import sys, struct, io
from elftools.elf.elffile import ELFFile

sys.path.insert(0, 'tools')
from metadata_v39 import Il2CppMetadataV39

with open('extracted_durak/global-metadata.dat', 'rb') as f:
    meta = Il2CppMetadataV39(f.read())

with open('extracted_durak/libil2cpp.so', 'rb') as f:
    data = f.read()

elf = ELFFile(io.BytesIO(data))
rela_dyn = elf.get_section_by_name('.rela.dyn')
rels = {r['r_offset']: r['r_addend'] for r in rela_dyn.iter_relocations()}

# Map all method pointers across all images
images = meta.get_images()
types = meta.get_type_definitions()

ro_sec = elf.get_section_by_name('.rodata')
ro_data = ro_sec.data()
ro_addr = ro_sec['sh_addr']

loads = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
def read_va(va, sz):
    for s in loads:
        if s['p_vaddr'] <= va < s['p_vaddr'] + s['p_filesz']:
            avail = min(sz, (s['p_vaddr'] + s['p_filesz']) - va)
            foff = s['p_offset'] + (va - s['p_vaddr'])
            return data[foff:foff+avail]
    return b''

def find_cgm(img_name):
    pos = 0
    mod_bytes = img_name.encode('utf-8') + b'\0'
    while True:
        idx = ro_data.find(mod_bytes, pos)
        if idx == -1: break
        str_va = ro_addr + idx
        for r_off, r_addend in rels.items():
            if r_addend == str_va:
                raw = read_va(r_off, 40)
                if len(raw) >= 40:
                    cnt = struct.unpack('<I', raw[16:20])[0]
                    arr = rels.get(r_off + 24, 0)
                    if cnt > 0 and arr != 0:
                        return arr, cnt
        pos = idx + 1
    return 0, 0

target_rvas = {
    0x17c4f08: '0x17c4f08',
    0x10c1898: '0x10c1898',
    0x10acf64: '0x10acf64',
    0xda3620:  '0xda3620',
    0xd49e0c:  '0xd49e0c',
    0xd79430:  '0xd79430',
    0xd7a518:  '0xd7a518',
    0xd7ae44:  '0xd7ae44',
    0x12089f4: '0x12089f4',
    0x12100dc: '0x12100dc',
    0x12106ac: '0x12106ac',
}

for img in images:
    name = img['name']
    arr, cnt = find_cgm(name)
    if not arr: continue
    t_start = img['type_start']
    t_cnt = img['type_count']
    for t_idx in range(t_start, t_start + t_cnt):
        t = types[t_idx]
        try:
            methods = meta.get_methods_for_type(t)
        except Exception:
            continue
        for m in methods:
            rid = m['rid']
            if 1 <= rid <= cnt:
                rva = rels.get(arr + (rid - 1) * 8, 0)
                if rva in target_rvas:
                    print(f"RVA 0x{rva:x} -> {img['name']} | {t['namespace']}.{t['name']}::{m['name']}")
