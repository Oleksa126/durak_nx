from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
import struct
import capstone

UNITY_PATH = "extracted_durak/sdmc/switch/durak_nx/game/lib/libunity.so"

def main():
    with open(UNITY_PATH, "rb") as f:
        elf = ELFFile(f)
        sections = {s.name: s for s in elf.iter_sections()}
        text_sec = sections['.text']
        text_data = text_sec.data()
        text_addr = text_sec['sh_addr']

        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

        # 1. References to 0x014634d8 in .text
        # ADRP page 0x1463000, off 0x4d8
        print("Searching references to 0x014634d8...")
        for i in range(0, len(text_data) - 8, 4):
            val = struct.unpack_from("<I", text_data, i)[0]
            # ADRP:
            if (val & 0x9f000000) == 0x90000000:
                immlo = (val >> 29) & 0x3
                immhi = (val >> 5) & 0x7ffff
                imm = (immhi << 2) | immlo
                if imm & 0x100000:
                    imm -= 0x200000
                pc = text_addr + i
                page = (pc & ~0xfff) + (imm << 12)
                if page == 0x01463000:
                    # check next instruction
                    val2 = struct.unpack_from("<I", text_data, i + 4)[0]
                    # ldr x..., [x..., #0x4d8]
                    # LDR (immediate, 64-bit): size=11, opc=01 -> 0xf9400000 | (imm12/8 << 10)
                    # 0x4d8 / 8 = 0x9b
                    if (val2 & 0xffc00000) == 0xf9400000 and ((val2 >> 10) & 0xfff) == 0x9b:
                        print(f"  Found reference to 0x014634d8 at 0x{pc:08x}:")
                        for insn in md.disasm(text_data[i-8:i+40], pc - 8):
                            print(f"    0x{insn.address:08x}: {insn.mnemonic:10} {insn.op_str}")

if __name__ == '__main__':
    main()
