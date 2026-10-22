from elftools.elf.elffile import ELFFile
import struct, capstone

def find_callers_of(target, name):
    print(f"=== Scanning callers of {name} (0x{target:08x}) ===")
    with open('extracted_durak/libunity.so', 'rb') as f:
        elf = ELFFile(f)
        text_sec = elf.get_section_by_name('.text')
        text_data = text_sec.data()
        text_addr = text_sec['sh_addr']

        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

        for i in range(0, len(text_data)-4, 4):
            val = struct.unpack_from("<I", text_data, i)[0]
            if (val & 0xfc000000) in [0x94000000, 0x14000000]: # bl or b
                imm26 = val & 0x03ffffff
                if imm26 & 0x02000000:
                    imm26 -= 0x04000000
                dest = text_addr + i + (imm26 * 4)
                if dest == target:
                    pc = text_addr + i
                    print(f"  Call from 0x{pc:08x}:")
                    start_off = max(0, i - 16)
                    end_off = min(len(text_data), i + 24)
                    for insn in md.disasm(text_data[start_off:end_off], start_off + text_addr):
                        p = "==>" if insn.address == pc else "   "
                        print(f"  {p} 0x{insn.address:08x}: {insn.mnemonic:10s} {insn.op_str}")

if __name__ == '__main__':
    find_callers_of(0x00e7257c, "Caller 1 (GetRefreshPeriod)")
    # Find enclosing function of Caller 2
    # In Caller 2, let's scan backwards for function prologue
    with open('extracted_durak/libunity.so', 'rb') as f:
        elf = ELFFile(f)
        text_sec = elf.get_section_by_name('.text')
        text_data = text_sec.data()
        text_addr = text_sec['sh_addr']
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        # scan back from 0xe72768
        for p in range(0x00e72768, 0x00e72700, -4):
            off = p - text_addr
            insn = list(md.disasm(text_data[off:off+4], p))[0]
            if insn.mnemonic == 'sub' and 'sp, sp' in insn.op_str:
                print(f"Caller 2 function starts at 0x{p:08x}: {insn.mnemonic} {insn.op_str}")
                find_callers_of(p, "Caller 2 enclosing function")
                break
            elif insn.mnemonic == 'stp' and '!' in insn.op_str and 'sp' in insn.op_str:
                print(f"Caller 2 function starts at 0x{p:08x}: {insn.mnemonic} {insn.op_str}")
                find_callers_of(p, "Caller 2 enclosing function")
                break
