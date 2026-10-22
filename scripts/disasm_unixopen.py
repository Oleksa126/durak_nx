import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
cs.detail = True

with open('extracted_durak/libsqlite3.so', 'rb') as f:
    data = f.read()

rva = 0x274ec
for insn in cs.disasm(data[rva:rva+160*4], rva):
    print(f"  0x{insn.address:08x}: {insn.mnemonic:8s} {insn.op_str}")
