from elftools.elf.elffile import ELFFile
import capstone

def main():
    with open('extracted_durak/libunity.so', 'rb') as f:
        elf = ELFFile(f)
        text_sec = elf.get_section_by_name('.text')
        text_data = text_sec.data()
        text_addr = text_sec['sh_addr']
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

        # Scan backward from 0x00e5737c to find function prologue
        for p in range(0x00e5737c, 0x00e56000, -4):
            off = p - text_addr
            insn = list(md.disasm(text_data[off:off+4], p))[0]
            if (insn.mnemonic == 'sub' and 'sp, sp' in insn.op_str) or \
               (insn.mnemonic == 'stp' and '!' in insn.op_str and 'sp' in insn.op_str):
                print(f"Function start at 0x{p:08x}: {insn.mnemonic} {insn.op_str}")
                # Print from function start to 0x00e57390
                off_start = p - text_addr
                for insn2 in md.disasm(text_data[off_start:off_start+160], p):
                    print(f"  0x{insn2.address:08x}: {insn2.mnemonic:10s} {insn2.op_str}")
                break

if __name__ == '__main__':
    main()
