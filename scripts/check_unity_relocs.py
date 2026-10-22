from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

UNITY_PATH = "extracted_durak/sdmc/switch/durak_nx/game/lib/libunity.so"

def main():
    with open(UNITY_PATH, "rb") as f:
        elf = ELFFile(f)
        for s in elf.iter_sections():
            if isinstance(s, RelocationSection):
                symtab = elf.get_section(s['sh_link'])
                for rel in s.iter_relocations():
                    # Check jump slot GOT offset
                    got_off = rel['r_offset']
                    sym_idx = rel['r_info_sym']
                    if sym_idx < symtab.num_symbols():
                        sym = symtab.get_symbol(sym_idx)
                        name = sym.name
                        if 'pthread_mutex' in name or 'pthread_cond' in name or 'choreographer' in name.lower() or 'vsync' in name.lower():
                            print(f"{name:32} GOT 0x{got_off:08x}")

if __name__ == '__main__':
    main()
