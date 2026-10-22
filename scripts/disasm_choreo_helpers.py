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

        funcs = [0x1011160, 0xe802c0, 0x10001fc, 0xe80250, 0x1000544, 0x1000e98, 0x100f1a0, 0x1011264]
        for fn in funcs:
            off = fn - text_addr
            print(f"=== Function 0x{fn:08x} ===")
            for insn in md.disasm(text_data[off:off+64], fn):
                print(f"  0x{insn.address:08x}: {insn.mnemonic:10} {insn.op_str}")

if __name__ == '__main__':
    main()
