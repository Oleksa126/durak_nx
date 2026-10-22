from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

UNITY_PATH = "extracted_durak/sdmc/switch/durak_nx/game/lib/libunity.so"

def main():
    with open(UNITY_PATH, "rb") as f:
        elf = ELFFile(f)
        targets = set(range(0x00e78900, 0x00e79200, 4))
        for s in elf.iter_sections():
            if isinstance(s, RelocationSection):
                for rel in s.iter_relocations():
                    addend = rel['r_addend']
                    if addend in targets:
                        print(f"Relocation {rel['r_info_type']} at 0x{rel['r_offset']:08x} with addend 0x{addend:08x}")

if __name__ == '__main__':
    main()
