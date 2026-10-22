import sys, struct, io
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True

with open('extracted_durak/libil2cpp.so', 'rb') as f:
    data = f.read()

# RVA to file offset:
# PT_LOAD 1: vaddr 0xb1cd30, offset 0xb18d30 -> foff = rva - 0x4000
def disasm(rva, num_insns=60):
    foff = rva - 0x4000
    code = data[foff:foff + num_insns * 4]
    print(f"\nDisassembly of 0x{rva:x}:")
    for insn in cs.disasm(code, rva):
        print(f"  0x{insn.address:08x}: {insn.mnemonic:8s} {insn.op_str}")

disasm(0x12100dc, 70) # SimpleSQLManager::Initialize
disasm(0x12089f4, 30) # SQLite3::Open
disasm(0xd474a8, 60)  # DataManager::InitializeDatabaseInfo
disasm(0xd476e8, 60)  # DataManager::DetectTables
disasm(0xd48178, 60)  # DataManager::UpdateDatabaseStructure
