import sys, struct
sys.path.insert(0, 'tools')
from metadata_v39 import Il2CppMetadataV39, SEC_FIELDS

with open('extracted_durak/global-metadata.dat', 'rb') as f:
    meta = Il2CppMetadataV39(f.read())

types = meta.get_type_definitions()
t_dm = next(t for t in types if t['name'] == 'DataManager')

f_off = meta.sections[SEC_FIELDS][0]
f_start = t_dm['field_start']
f_cnt = t_dm['field_count']
print(f"DataManager fields (start={f_start}, count={f_cnt}):")

for i in range(f_start, f_start + f_cnt):
    chunk = meta.data[f_off + i * 10 : f_off + (i + 1) * 10]
    name_idx = struct.unpack('<I', chunk[:4])[0]
    fname = meta.get_string(name_idx)
    print(f"  Field [{i - f_start}]: {fname}")
