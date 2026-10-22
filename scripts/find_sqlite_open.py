import io
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

with open('extracted_durak/libsqlite3.so', 'rb') as f:
    data = f.read()

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True

elf = ELFFile(io.BytesIO(data))
dynsym = elf.get_section_by_name('.dynsym')
syms = {s.name: s['st_value'] for s in dynsym.iter_symbols()}

print("sqlite3_open RVA:", hex(syms.get('sqlite3_open', 0)))
print("sqlite3_open_v2 RVA:", hex(syms.get('sqlite3_open_v2', 0)))

# Let's find unixOpen
# unixOpen is registered in sqlite3_os_init or aVfs
# Let's search data for 'unix' vfs name
vfs_name_idx = data.find(b'unix-none\0')
if vfs_name_idx == -1: vfs_name_idx = data.find(b'unix\0')
print("VFS name 'unix' at:", hex(vfs_name_idx))
