from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
import capstone
import struct

UNITY_PATH = "extracted_durak/sdmc/switch/durak_nx/game/lib/libunity.so"

def main():
    with open(UNITY_PATH, "rb") as f:
        elf = ELFFile(f)
        sections = {s.name: s for s in elf.iter_sections()}
        text_sec = sections['.text']
        text_data = text_sec.data()
        text_addr = text_sec['sh_addr']
        rodata_sec = sections['.rodata']
        rodata_data = rodata_sec.data()
        rodata_addr = rodata_sec['sh_addr']

        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        md.detail = True

        # 1. Let's find PLT stubs for pthread_cond_signal and pthread_cond_broadcast
        # GOT entries found earlier:
        # pthread_cond_broadcast GOT 0x01454488
        # pthread_cond_signal    GOT 0x01454490
        # Let's find their PLT entries
        plt_sec = sections['.plt']
        plt_data = plt_sec.data()
        plt_addr = plt_sec['sh_addr']

        cond_signals = {}
        for i in range(32, len(plt_data), 16):
            va = plt_addr + i
            chunk = plt_data[i:i+16]
            insns = list(md.disasm(chunk, va))
            adrp_val = None
            for insn in insns:
                if insn.mnemonic == 'adrp':
                    adrp_val = insn.operands[1].imm
                elif insn.mnemonic == 'ldr' and adrp_val is not None:
                    target = adrp_val + insn.operands[1].mem.disp
                    if target in [0x01454488, 0x01454490]:
                        name = "pthread_cond_broadcast" if target == 0x01454488 else "pthread_cond_signal"
                        cond_signals[va] = name
                        print(f"PLT stub for {name} @ 0x{va:08x}")

        # 2. Look for all calls (BL) to cond_signals around 0xe78000 to 0xe82000
        print("\nScanning calls to pthread_cond_signal/broadcast in 0xe70000 - 0xe85000...")
        start_off = 0xe70000 - text_addr
        end_off = 0xe85000 - text_addr
        for i in range(start_off, end_off, 4):
            val = struct.unpack_from("<I", text_data, i)[0]
            if (val & 0xfc000000) == 0x94000000:
                imm26 = val & 0x03ffffff
                if imm26 & 0x02000000:
                    imm26 -= 0x04000000
                target = text_addr + i + (imm26 * 4)
                if target in cond_signals:
                    call_name = cond_signals[target]
                    call_va = text_addr + i
                    print(f"Call to {call_name} at 0x{call_va:08x}:")
                    start = max(0, i - 48)
                    for insn in md.disasm(text_data[start:i+16], text_addr + start):
                        prefix = "==>" if insn.address == call_va else "   "
                        print(f"{prefix} 0x{insn.address:08x}: {insn.mnemonic:10} {insn.op_str}")
                    print("-" * 60)

        # 3. Look for strings related to Choreographer in rodata
        print("\nSearching Choreographer strings in rodata...")
        pos = 0
        while True:
            idx = rodata_data.lower().find(b"choreographer", pos)
            if idx == -1:
                break
            # Find start and end of string
            s_start = rodata_data.rfind(b"\0", 0, idx)
            s_start = 0 if s_start == -1 else s_start + 1
            s_end = rodata_data.find(b"\0", idx)
            s_end = len(rodata_data) if s_end == -1 else s_end
            s_val = rodata_data[s_start:s_end].decode('utf-8', errors='replace')
            print(f"rodata @ 0x{rodata_addr + s_start:08x}: {repr(s_val)}")
            pos = idx + len(b"choreographer")

if __name__ == '__main__':
    main()
