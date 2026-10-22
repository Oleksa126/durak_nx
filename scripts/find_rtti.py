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
                    if 0x01431f50 <= rel['r_offset'] <= 0x01432000:
                        sym_name = ""
                        if rel['r_info_sym'] < symtab.num_symbols():
                            sym_name = symtab.get_symbol(rel['r_info_sym']).name
                        print(f"Reloc at 0x{rel['r_offset']:08x} -> addend 0x{rel['r_addend']:08x} sym '{sym_name}'")

if __name__ == '__main__':
    main()
