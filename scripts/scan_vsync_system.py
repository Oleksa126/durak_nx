from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
import struct, capstone

def find_refs(targets):
    with open('extracted_durak/libunity.so', 'rb') as f:
        elf = ELFFile(f)
        text_sec = elf.get_section_by_name('.text')
        text_data = text_sec.data()
        text_addr = text_sec['sh_addr']
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

        for target, name in targets.items():
            print(f"\n=======================================================")
            print(f"Scanning for calls/refs to {name} (0x{target:08x})...")
            print(f"=======================================================")

            # Direct calls (bl or b)
            for i in range(0, len(text_data)-4, 4):
                val = struct.unpack_from('<I', text_data, i)[0]
                if (val & 0xfc000000) in [0x94000000, 0x14000000]:
                    imm26 = val & 0x03ffffff
                    if imm26 & 0x02000000:
                        imm26 -= 0x04000000
                    dest = text_addr + i + (imm26 * 4)
                    if dest == target:
                        pc = text_addr + i
                        print(f"Direct branch from 0x{pc:08x}:")
                        start_off = max(0, i - 24)
                        end_off = min(len(text_data), i + 36)
                        for insn in md.disasm(text_data[start_off:end_off], start_off + text_addr):
                            p = "==>" if insn.address == pc else "   "
                            print(f"  {p} 0x{insn.address:08x}: {insn.mnemonic:10s} {insn.op_str}")

            # Pointers in data sections or vtables
            for s in elf.iter_sections():
                if isinstance(s, RelocationSection):
                    for rel in s.iter_relocations():
                        if rel['r_addend'] == target:
                            print(f"Relocation {rel['r_info_type']} at 0x{rel['r_offset']:08x} with addend 0x{target:08x}")
                elif s.name in ['.rodata', '.data', '.data.rel.ro']:
                    d = s.data()
                    for i in range(0, len(d)-8, 8):
                        if struct.unpack_from('<Q', d, i)[0] == target:
                            print(f"Data pointer at {s.name}+0x{i:x} (addr 0x{s['sh_addr']+i:08x})")

if __name__ == '__main__':
    find_refs({
        0x00e72440: "WaitForVsyncFrame (hang function)",
        0x00e724a0: "OnVsync (increment & broadcast)",
        0x00e724f8: "GetFrameStats",
    })
