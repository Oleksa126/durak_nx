import sys, struct
sys.path.insert(0, 'tools')
from metadata_v39 import Il2CppMetadataV39, SEC_TYPE_DEFINITIONS, SEC_FIELDS, SEC_FIELD_DEFAULT_VALUES

with open('extracted_durak/global-metadata.dat', 'rb') as f:
    meta = Il2CppMetadataV39(f.read())

types = meta.get_type_definitions()
t_ssm = next(t for t in types if t['name'] == 'SimpleSQLManager')

f_off, _, f_count = meta.sections[SEC_FIELDS]
f_start = t_ssm['field_start']
f_cnt = t_ssm['field_count']
print(f"SimpleSQLManager fields (start={f_start}, count={f_cnt}):")

# FieldDefinition in v39: nameIndex(4), typeIndex(4), customAttributeIndex(4), token(4) -> 16 bytes (or check size)
# Let's check field size
field_size = meta.sections[SEC_FIELDS][1] // meta.sections[SEC_FIELDS][2]
print(f"Field size: {field_size}")

for i in range(f_start, f_start + f_cnt):
    chunk = meta.data[f_off + i * field_size : f_off + (i + 1) * field_size]
    name_idx = struct.unpack('<I', chunk[:4])[0]
    fname = meta.get_string(name_idx)
    print(f"  Field [{i - f_start}]: {fname}")
