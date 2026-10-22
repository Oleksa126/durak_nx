from elftools.elf.elffile import ELFFile
import capstone

UNITY_PATH = "extracted_durak/sdmc/switch/durak_nx/game/lib/libunity.so"

def main():
    with open(UNITY_PATH, "rb") as f:
        elf = ELFFile(f)
        text_sec = [s for s in elf.iter_sections() if s.name == '.text'][0]
        text_data = text_sec.data()
        text_addr = text_sec['sh_addr']

        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        md.detail = True

        # Search for adrp/add loading 0x000e4eb2 (UnityChoreographer) or 0x000d0800
        targets = [0x000e4eb2, 0x000d0800, 0x0010cbd4, 0x00173cee, 0x00173cd3]
        for t in targets:
            page = t & ~0xfff
            page_off = t & 0xfff
            print(f"Searching references to 0x{t:08x} (page 0x{page:08x}, off 0x{page_off:03x})...")
            for i in range(0, len(text_data) - 8, 4):
                insns = list(md.disasm(text_data[i:i+8], text_addr + i))
                if len(insns) == 2:
                    i0, i1 = insns[0], insns[1]
                    if i0.mnemonic == 'adrp' and i0.operands[1].imm == page:
                        if i1.mnemonic in ['add', 'ldr'] and i1.op_str.endswith(f"#{hex(page_off)}"):
                            print(f"  Found at 0x{i0.address:08x}:")
                            start = max(0, i - 16)
                            for insn in md.disasm(text_data[start:i+48], text_addr + start):
                                print(f"    0x{insn.address:08x}: {insn.mnemonic:10} {insn.op_str}")

if __name__ == '__main__':
    main()
