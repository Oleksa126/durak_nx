from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

UNITY_PATH = "extracted_durak/sdmc/switch/durak_nx/game/lib/libunity.so"

def main():
    with open(UNITY_PATH, "rb") as f:
        elf = ELFFile(f)
        sections = {s.name: s for s in elf.iter_sections()}
        rodata = sections['.rodata']
        rodata_data = rodata.data()
        rodata_addr = rodata['sh_addr']

        for s in elf.iter_sections():
            if isinstance(s, RelocationSection):
                symtab = elf.get_section(s['sh_link'])
                for rel in s.iter_relocations():
                    if 0x01587000 <= rel['r_offset'] <= 0x01588000:
                        addend = rel['r_addend']
                        name = ""
                        if rel['r_info_sym'] < symtab.num_symbols():
                            name = symtab.get_symbol(rel['r_info_sym']).name
                        print(f"Reloc at 0x{rel['r_offset']:08x} -> 0x{addend:08x} '{name}'")
                        if rodata_addr <= addend < rodata_addr + len(rodata_data):
                            off = addend - rodata_addr
                            end = rodata_data.find(b'\0', off)
                            print(f"    String: {repr(rodata_data[off:end])}")

if __name__ == '__main__':
    main()
