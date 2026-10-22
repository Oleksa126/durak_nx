from elftools.elf.elffile import ELFFile
import capstone
import struct

UNITY_PATH = "extracted_durak/sdmc/switch/durak_nx/game/lib/libunity.so"

def main():
    with open(UNITY_PATH, "rb") as f:
        elf = ELFFile(f)
        sections = {s.name: s for s in elf.iter_sections()}
        text_sec = sections['.text']
        text_data = text_sec.data()
        text_addr = text_sec['sh_addr']

        target = 0x00e789e8
        print(f"Scanning calls to 0x{target:08x} in libunity.so...")
        for i in range(0, len(text_data) - 4, 4):
            val = struct.unpack_from("<I", text_data, i)[0]
            if (val & 0xfc000000) == 0x94000000:
                imm26 = val & 0x03ffffff
                if imm26 & 0x02000000:
                    imm26 -= 0x04000000
                dest = text_addr + i + (imm26 * 4)
                if dest == target:
                    print(f"Call to 0x{target:08x} at 0x{text_addr+i:08x}")

        # Also check references to 0x00e789e8 in data/rodata (vtable or func ptr)
        for s in elf.iter_sections():
            if s.name in ['.rodata', '.data', '.data.rel.ro']:
                s_data = s.data()
                s_addr = s['sh_addr']
                for i in range(0, len(s_data) - 8, 8):
                    ptr = struct.unpack_from("<Q", s_data, i)[0]
                    if ptr == target:
                        print(f"Pointer to 0x{target:08x} at {s.name} + 0x{i:x} (addr 0x{s_addr+i:08x})")

if __name__ == '__main__':
    main()
