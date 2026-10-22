import sys, struct, io
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

sys.path.insert(0, 'tools')
from metadata_v39 import Il2CppMetadataV39

with open('extracted_durak/global-metadata.dat', 'rb') as f:
    meta = Il2CppMetadataV39(f.read())

with open('extracted_durak/libil2cpp.so', 'rb') as f:
    data = f.read()

elf = ELFFile(io.BytesIO(data))
rela_dyn = elf.get_section_by_name('.rela.dyn')
rels = {r['r_offset']: r['r_addend'] for r in rela_dyn.iter_relocations()}

# Map of images to (mp_array, mp_count)
cgm_map = {
    'SimpleSQL_Runtime.dll': (0x1d6c330, 304),
    'Assembly-CSharp.dll': (0x1c3b158, 2865)
}

images = meta.get_images()
types = meta.get_type_definitions()

for img in images:
    name = img['name']
    if name not in cgm_map: continue
    mp_array, mp_count = cgm_map[name]
    t_start = img['type_start']
    t_cnt = img['type_count']
    for t_idx in range(t_start, t_start + t_cnt):
        t = types[t_idx]
        t_name = t['name']
        if any(k in t_name for k in ['SimpleSQL', 'SQLite', 'SinglePlayer', 'Stats', 'GameManager', 'Save', 'Data']):
            print(f"\n=== Image: {name} | Type: {t_name} (idx: {t_idx}) ===")
            methods = meta.get_methods_for_type(t)
            for m in methods:
                rid = m['rid']
                if 1 <= rid <= mp_count:
                    rva = rels.get(mp_array + (rid - 1) * 8, 0)
                    print(f"  {m['name']}: RVA=0x{rva:x} (token=0x{m['token']:x})")
