from elftools.elf.elffile import ELFFile
import struct
import capstone

UNITY_PATH = "extracted_durak/sdmc/switch/durak_nx/game/lib/libunity.so"

def decode_adrp(val, pc):
    # ADRP: [31] 1 [30:29] immlo [28:24] 10000 [23:5] immhi [4:0] Rd
    if (val & 0x9f000000) != 0x90000000:
        return None, None
    rd = val & 0x1f
    immlo = (val >> 29) & 0x3
    immhi = (val >> 5) & 0x7ffff
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    page = (pc & ~0xfff) + (imm << 12)
    return rd, page

def main():
    with open(UNITY_PATH, "rb") as f:
        elf = ELFFile(f)
        text_sec = [s for s in elf.iter_sections() if s.name == '.text'][0]
        text_data = text_sec.data()
        text_addr = text_sec['sh_addr']

        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

        targets = [
            (0x000e4eb2, "UnityChoreographer"),
            (0x000d0800, "android/view/Choreographer$FrameCallback"),
            (0x0010b87a, "Using Java Choreographer."),
            (0x0015c021, "Using NDK Choreographer."),
            (0x0011b84a, "ChoreographerNDK: Ignoring event, since Choreographer is disabled"),
            (0x00142176, "ChoreographerNDK: Ignoring event, since data is null"),
        ]

        target_pages = {t & ~0xfff: [] for t, _ in targets}
        for t, name in targets:
            target_pages[t & ~0xfff].append((t, name))

        print("Scanning text section for target page references...")
        for i in range(0, len(text_data) - 4, 4):
            pc = text_addr + i
            val = struct.unpack_from("<I", text_data, i)[0]
            rd, page = decode_adrp(val, pc)
            if page in target_pages:
                # Check next few instructions for reference to target
                chunk = text_data[i:i+32]
                for insn in md.disasm(chunk, pc):
                    for t, name in target_pages[page]:
                        poff = t & 0xfff
                        if f"#{hex(poff)}" in insn.op_str or f"#{poff}" in insn.op_str:
                            print(f"\n[!] Reference to '{name}' (0x{t:08x}) at 0x{insn.address:08x}:")
                            start = max(0, i - 16)
                            for insn2 in md.disasm(text_data[start:i+64], text_addr + start):
                                print(f"    0x{insn2.address:08x}: {insn2.mnemonic:10} {insn2.op_str}")

if __name__ == '__main__':
    main()
