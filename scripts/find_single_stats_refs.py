import sys, struct, io
from elftools.elf.elffile import ELFFile

sys.path.insert(0, 'tools')
from metadata_v39 import Il2CppMetadataV39

with open('extracted_durak/global-metadata.dat', 'rb') as f:
    meta = Il2CppMetadataV39(f.read())

types = meta.get_type_definitions()
t_ss = next(t for t in types if t['name'] == 'single_stats')
print(f"single_stats type index: {t_ss['type_index']}, namespace: {t_ss['namespace']}")

# Find all references to single_stats type index or token in metadata
# Let's search metadata for t_ss['type_index'] as uint32 or token as uint32
target_idx = t_ss['type_index']
target_token = t_ss['token']
print(f"target_idx: {target_idx}, target_token: 0x{target_token:x}")

with open('extracted_durak/libil2cpp.so', 'rb') as f:
    data = f.read()

# Search stringLiteralData for single_stats
idx = data.find(b'single_stats\0')
print(f"single_stats string in libil2cpp.so at: 0x{idx:x}")

# Let's search where 'single_stats' string is referenced in relocations
elf = ELFFile(io.BytesIO(data))
rela_dyn = elf.get_section_by_name('.rela.dyn')
rels = {r['r_offset']: r['r_addend'] for r in rela_dyn.iter_relocations()}

matching_rels = [hex(k) for k, v in rels.items() if v == idx]
print("Relocations to 'single_stats':", matching_rels)
