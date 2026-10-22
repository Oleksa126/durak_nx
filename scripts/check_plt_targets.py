from elftools.elf.elffile import ELFFile
import capstone

UNITY_PATH = "extracted_durak/sdmc/switch/durak_nx/game/lib/libunity.so"

def main():
    with open(UNITY_PATH, "rb") as f:
        elf = ELFFile(f)
        sections = {s.name: s for s in elf.iter_sections()}
        text_sec = sections['.text']
        plt_sec = sections['.plt']
        plt_data = plt_sec.data()
        plt_addr = plt_sec['sh_addr']

        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        md.detail = True

        for target in [0x1401b40, 0x1401b50, 0x1402020]:
            off = target - plt_addr
            chunk = plt_data[off:off+16]
            insns = list(md.disasm(chunk, target))
            adrp_val = None
            got_target = None
            for insn in insns:
                if insn.mnemonic == 'adrp':
                    adrp_val = insn.operands[1].imm
                elif insn.mnemonic == 'ldr' and adrp_val is not None:
                    got_target = adrp_val + insn.operands[1].mem.disp
                    break
            print(f"PLT 0x{target:08x} -> GOT 0x{got_target:08x}")

if __name__ == '__main__':
    main()
