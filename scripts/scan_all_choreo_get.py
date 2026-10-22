from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
import struct, capstone

def scan_lib(path):
    print(f"=== Scanning {path} ===")
    with open(path, "rb") as f:
        elf = ELFFile(f)
        text_sec = elf.get_section_by_name(".text")
        text_data = text_sec.data()
        text_addr = text_sec["sh_addr"]

        target = 0x00e7261c
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

        # 1. Direct branch/call
        for i in range(0, len(text_data)-4, 4):
            val = struct.unpack_from("<I", text_data, i)[0]
            if (val & 0xfc000000) in [0x94000000, 0x14000000]: # bl or b
                imm26 = val & 0x03ffffff
                if imm26 & 0x02000000:
                    imm26 -= 0x04000000
                dest = text_addr + i + (imm26 * 4)
                if dest == target:
                    pc = text_addr + i
                    print(f"\nDirect branch to 0x{target:08x} at 0x{pc:08x}:")
                    start_off = max(0, i - 32)
                    end_off = min(len(text_data), i + 48)
                    ctx_start = start_off + text_addr
                    for insn in md.disasm(text_data[start_off:end_off], ctx_start):
                        prefix = "==>" if insn.address == pc else "   "
                        print(f"{prefix} 0x{insn.address:08x}: {insn.mnemonic:10s} {insn.op_str}")

        # 2. Relocations / Pointers in data sections
        for s in elf.iter_sections():
            if isinstance(s, RelocationSection):
                for rel in s.iter_relocations():
                    if rel['r_addend'] == target:
                        print(f"Relocation at 0x{rel['r_offset']:08x} with addend 0x{target:08x}")
            elif s.name in ['.rodata', '.data', '.data.rel.ro']:
                data = s.data()
                s_addr = s['sh_addr']
                for i in range(0, len(data)-8, 8):
                    ptr = struct.unpack_from("<Q", data, i)[0]
                    if ptr == target:
                        print(f"Pointer to 0x{target:08x} at {s.name}+0x{i:x} (addr 0x{s_addr+i:08x})")

if __name__ == '__main__':
    scan_lib('extracted_durak/libunity.so')
    scan_lib('extracted_durak/libil2cpp.so')
