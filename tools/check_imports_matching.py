import os
import re
import json
from elftools.elf.elffile import ELFFile

symbols_in_c = {}
for fname in ["source/imports.c", "source/unity_imports.c", "source/firebase_stub.c"]:
    if os.path.exists(fname):
        with open(fname, "r") as f:
            text = f.read()
        entries = re.findall(r'\{\s*"([^"]+)"\s*,\s*\(uintptr_t\)\s*([^}]+)\}', text)
        for e in entries:
            symbols_in_c[e[0]] = e[1].strip()

print(f"Total symbols defined in runtime (*.c): {len(symbols_in_c)}")

modules = ['libsqlite3.so', 'libmain.so', 'libunity.so', 'libil2cpp.so']
exports = {}
imports = {}

for m in modules:
    path = 'extracted_durak/' + m
    exports[m] = set()
    imports[m] = []
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        dynsym = elf.get_section_by_name('.dynsym')
        for sym in dynsym.iter_symbols():
            shndx = sym['st_shndx']
            bind = sym['st_info']['bind']
            st_type = sym['st_info']['type']
            name = sym.name
            if shndx != 'SHN_UNDEF' and bind != 'STB_LOCAL':
                exports[m].add(name)
            elif shndx == 'SHN_UNDEF' and name:
                imports[m].append((name, bind, st_type))

all_exports = set()
for m in modules:
    all_exports.update(exports[m])

all_needed_imports = set()
for m in modules:
    for name, bind, st_type in imports[m]:
        all_needed_imports.add(name)

print(f"Total unique import symbol names across all 4 modules: {len(all_needed_imports)}")

missing_from_runtime = []
for sym in sorted(all_needed_imports):
    if sym in symbols_in_c:
        continue
    if sym in all_exports:
        continue
    missing_from_runtime.append(sym)

print(f"Total unresolved (not in imports.c and not exported by any module): {len(missing_from_runtime)}")
for sym in missing_from_runtime:
    print(f"  MISSING: {sym}")
