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
cgm_table = {
    'Assembly-CSharp.dll': (0x1c3b158, 2865),
    'SimpleSQL_Runtime.dll': (0x1d6c330, 304),
    'UnityEngine.CoreModule.dll': (0x1da51d8, 3884),
    'mscorlib.dll': (0x1d4b228, 12295),
}

# Build reverse map: RVA -> (Image, Type, Method)
rva_map = {}
types = meta.get_type_definitions()
for img in meta.get_images():
    img_name = img['name']
    if img_name not in cgm_table: continue
    mp_array, mp_count = cgm_table[img_name]
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
            if 1 <= rid <= mp_count:
                rva = rels.get(mp_array + (rid - 1) * 8, 0)
                if rva:
                    ns = t['namespace']
                    tname = ns + '.' + t['name'] if ns else t['name']
                    rva_map[rva] = f"{tname}::{m['name']}"

print(f"Total mapped RVAs: {len(rva_map)}")

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True

def disasm_and_resolve(rva, count=100):
    foff = rva - 0x4000
    code = data[foff:foff + count * 4]
    name = rva_map.get(rva, f"0x{rva:x}")
    print(f"\n=== Disassembly of {name} (RVA 0x{rva:x}) ===")
    for insn in cs.disasm(code, rva):
        line = f"  0x{insn.address:08x}: {insn.mnemonic:8s} {insn.op_str}"
        # Check if bl or b to known target
        if insn.mnemonic in ('bl', 'b'):
            try:
                target = int(insn.op_str.lstrip('#'), 16)
                if target in rva_map:
                    line += f"  ; -> {rva_map[target]}"
            except Exception:
                pass
        print(line)

# Let's disassemble SinglePlayerSelect::redrawGameList
# and SinglePlayerSelect::Start
# and SinglePlayerSelect::OnEnable
disasm_and_resolve(0xd79430, 80) # SinglePlayerSelect::redrawGameList
disasm_and_resolve(0xd7ae44, 80) # SinglePlayerSelect::OnEnable
