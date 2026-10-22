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

        # Disassemble 0x1402020 and 0x1401b50 to see what they are
        for target in [0x1402020, 0x1401b50]:
            print(f"--- Disassembly of 0x{target:08x} ---")
            off = target - text_addr
            for insn in md.disasm(text_data[off:off+32], target):
                print(f"  0x{insn.address:08x}: {insn.mnemonic:10} {insn.op_str}")

        # Find start of the function containing 0xe78b38
        # Scan backward from 0xe78b38 for prologue (stp x29, x30, ... or sub sp, sp, ...)
        rva = 0xe78b38
        start_scan = rva - 512
        off_scan = start_scan - text_addr
        insns = list(md.disasm(text_data[off_scan:off_scan+600], start_scan))

        # Print the whole function from its start
        fn_start = None
        for i, insn in enumerate(insns):
            # Typical prologue: stp x..., x..., [sp, #-...]!
            if insn.address <= rva:
                if insn.mnemonic == 'stp' and '!' in insn.op_str and 'sp' in insn.op_str:
                    fn_start = insn.address
                elif insn.mnemonic == 'sub' and insn.op_str.startswith('sp, sp'):
                    fn_start = insn.address

        print(f"\nFunction start estimated at: 0x{fn_start:08x}")
        if fn_start:
            off_fn = fn_start - text_addr
            print(f"--- Function disassembly from 0x{fn_start:08x} to 0x{rva+32:08x} ---")
            for insn in md.disasm(text_data[off_fn:off_fn+(rva+32-fn_start)], fn_start):
                prefix = "==>" if insn.address == rva else "   "
                print(f"{prefix} 0x{insn.address:08x}: {insn.mnemonic:10} {insn.op_str}")

if __name__ == '__main__':
    main()
