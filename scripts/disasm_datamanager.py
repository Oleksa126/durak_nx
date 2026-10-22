import sys, struct, io
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True

with open('extracted_durak/libil2cpp.so', 'rb') as f:
    data = f.read()

# Load metadata string table & string literals
with open('extracted_durak/global-metadata.dat', 'rb') as f:
    meta_bytes = f.read()

sys.path.insert(0, 'tools')
from metadata_v39 import Il2CppMetadataV39
meta = Il2CppMetadataV39(meta_bytes)

# Disassemble and print string references and branch targets
def disasm_func(rva, count=100):
    foff = rva - 0x4000
    code = data[foff:foff + count * 4]
    print(f"\n=== Function at RVA 0x{rva:x} ===")
    for insn in cs.disasm(code, rva):
        print(f"  0x{insn.address:08x}: {insn.mnemonic:8s} {insn.op_str}")

disasm_func(0xd49fa8, 50) # DataManager::CreateTable
disasm_func(0xd474a8, 60) # DataManager::InitializeDatabaseInfo
disasm_func(0xd476e8, 70) # DataManager::DetectTables
