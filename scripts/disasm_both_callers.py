from elftools.elf.elffile import ELFFile
import capstone

def disasm_func_range(start, end, label):
    print(f"=== {label} (0x{start:08x} - 0x{end:08x}) ===")
    with open('extracted_durak/libunity.so', 'rb') as f:
        elf = ELFFile(f)
        text_sec = elf.get_section_by_name('.text')
        text_data = text_sec.data()
        text_addr = text_sec['sh_addr']

        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        off = start - text_addr
        length = end - start
        for insn in md.disasm(text_data[off:off+length], start):
            print(f"  0x{insn.address:08x}: {insn.mnemonic:10s} {insn.op_str}")

if __name__ == '__main__':
    # Caller 1: around 0xe7257c - 0xe72618
    disasm_func_range(0x00e7257c, 0x00e7261c, "Caller 1: GetRefreshPeriod (or similar)")
    # Caller 2: around 0xe72768 - 0x00e72790
    disasm_func_range(0x00e72768, 0x00e72790, "Caller 2: Register/Unregister or Callback")
