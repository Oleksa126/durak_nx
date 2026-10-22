from elftools.elf.elffile import ELFFile
import capstone

def main():
    with open('extracted_durak/libunity.so', 'rb') as f:
        elf = ELFFile(f)
        text_sec = elf.get_section_by_name('.text')
        text_data = text_sec.data()
        text_addr = text_sec['sh_addr']
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

        start = 0x00e79600
        end = 0x00e79700
        off = start - text_addr
        print(f"=== Disassembly from 0x{start:08x} to 0x{end:08x} ===")
        for insn in md.disasm(text_data[off:off+(end-start)], start):
            print(f"  0x{insn.address:08x}: {insn.mnemonic:10s} {insn.op_str}")

if __name__ == '__main__':
    main()
