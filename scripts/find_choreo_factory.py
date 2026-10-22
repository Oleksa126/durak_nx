from elftools.elf.elffile import ELFFile
import struct
import capstone

UNITY_PATH = "extracted_durak/sdmc/switch/durak_nx/game/lib/libunity.so"

def decode_adrp(val, pc):
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
        md.detail = True

        target = 0x00146ea7
        target_page = target & ~0xfff
        target_off = target & 0xfff

        print(f"Searching references to 0x{target:08x} (page 0x{target_page:08x}, off 0x{target_off:03x})...")
        for i in range(0, len(text_data) - 4, 4):
            pc = text_addr + i
            val = struct.unpack_from("<I", text_data, i)[0]
            rd, page = decode_adrp(val, pc)
            if page == target_page:
                chunk = text_data[i:i+32]
                for insn in md.disasm(chunk, pc):
                    if f"#{hex(target_off)}" in insn.op_str or f"#{target_off}" in insn.op_str:
                        print(f"\n[!] Reference at 0x{insn.address:08x}:")
                        start = max(0, i - 128)
                        end = min(len(text_data), i + 256)
                        for insn2 in md.disasm(text_data[start:end], text_addr + start):
                            prefix = "==>" if insn2.address == insn.address else "   "
                            print(f"{prefix} 0x{insn2.address:08x}: {insn2.mnemonic:10} {insn2.op_str}")

if __name__ == '__main__':
    main()
