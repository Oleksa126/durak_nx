from elftools.elf.elffile import ELFFile
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
        md.detail = True

        start_va = 0x00e78bb0
        end_va = 0x00e78f00
        off = start_va - text_addr
        len_b = end_va - start_va

        print(f"--- Disassembly from 0x{start_va:08x} to 0x{end_va:08x} ---")
        for insn in md.disasm(text_data[off:off+len_b], start_va):
            print(f"0x{insn.address:08x}: {insn.mnemonic:10} {insn.op_str}")

if __name__ == '__main__':
    main()
