import sys, struct
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

sys.path.insert(0, 'tools')
from metadata_v39 import Il2CppMetadataV39

with open('extracted_durak/global-metadata.dat', 'rb') as f:
    meta = Il2CppMetadataV39(f.read())

elf_file = open('extracted_durak/libil2cpp.so', 'rb')
elf = ELFFile(elf_file)
ro_sec = elf.get_section_by_name('.rodata')
ro_data = ro_sec.data()
ro_addr = ro_sec['sh_addr']
rela_dyn = elf.get_section_by_name('.rela.dyn')
rels = {r['r_offset']: r['r_addend'] for r in rela_dyn.iter_relocations()}

loads = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
def read_va(va, sz):
    for s in loads:
        if s['p_vaddr'] <= va < s['p_vaddr'] + s['p_filesz']:
            avail = min(sz, (s['p_vaddr'] + s['p_filesz']) - va)
            elf_file.seek(s['p_offset'] + (va - s['p_vaddr']))
            return elf_file.read(avail)
    return b''

def find_codegen_module(module_name):
    pos = 0
    mod_bytes = module_name.encode('utf-8') + b'\0'
    while True:
        idx = ro_data.find(mod_bytes, pos)
        if idx == -1: break
        str_va = ro_addr + idx
        for r_off, r_addend in rels.items():
            if r_addend == str_va:
                raw_cgm = read_va(r_off, 40)
                if len(raw_cgm) >= 40:
                    mp_count = struct.unpack('<I', raw_cgm[16:20])[0]
                    mp_array_va = rels.get(r_off + 24, 0)
                    if mp_count > 0 and mp_array_va != 0:
                        return r_off, mp_array_va, mp_count
        pos = idx + 1
    return None, None, 0

images = meta.get_images()
types = meta.get_type_definitions()

for img_name in ['SimpleSQL_Runtime.dll', 'Assembly-CSharp.dll']:
    cgm_va, mp_array_va, mp_count = find_codegen_module(img_name)
    print(f"CGM for {img_name}: va=0x{cgm_va:x}, mp_array=0x{mp_array_va:x}, count={mp_count}")

    img = next(i for i in images if i['name'] == img_name)
    t_start = img['type_start']
    t_cnt = img['type_count']
    for t_idx in range(t_start, t_start + t_cnt):
        t = types[t_idx]
        t_name = t['name']
        if t_name in ['SimpleSQLManager', 'SQLiteConnection', 'SinglePlayerSelect', 'single_stats', 'PlayerStats', 'DataBaseManager', 'DBManager']:
            print(f"\n--- Type: {t_name} ---")
            methods = meta.get_methods_for_type(t)
            for m in methods:
                rid = m['rid']
                if 1 <= rid <= mp_count:
                    rva = rels.get(mp_array_va + (rid - 1) * 8, 0)
                    print(f"  {m['name']}: RVA=0x{rva:x} (token=0x{m['token']:x})")
