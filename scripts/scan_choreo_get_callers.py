from elftools.elf.elffile import ELFFile
import struct
import capstone

UNITY_PATH = "extracted_durak/sdmc/switch/durak_nx/game/lib/libunity.so"

def main():
    with open(UNITY_PATH, "rb") as f:
        elf = ELFFile(f)
        text_sec = [s for s in elf.iter_sections() if s.name == '.text'][0]
        text_data = text_sec.data()
        text_addr = text_sec['sh_addr']

        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

        target = 0x00e7261c
        print(f"Scanning calls to ChoreographerBase::Get @ 0x{target:08x} in libunity.so...")
        for i in range(0, len(text_data) - 4, 4):
            val = struct.unpack_from("<I", text_data, i)[0]
            if (val & 0xfc000000) == 0x94000000:
                imm26 = val & 0x03ffffff
                if imm26 & 0x02000000:
                    imm26 -= 0x04000000
                dest = text_addr + i + (imm26 * 4)
                if dest == target:
                    caller_va = text_addr + i
                    print(f"\nCall from 0x{caller_va:08x}:")
                    start = max(0, i - 16)
                    end = min(len(text_data), i + 32)
                    for insn in md.disasm(text_data[start:end], text_addr + start):
                        prefix = "==>" if insn.address == caller_va else "   "
                        print(f"{prefix} 0x{insn.address:08x}: {insn.mnemonic:10} {insn.op_str}")

if __name__ == '__main__':
    main()
