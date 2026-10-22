"""Check the assembled fallback against actual displaced ARM64 instructions."""
import io
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile
root=Path(__file__).resolve().parents[1]
elf=ELFFile(io.BytesIO((root/'build-obj/static_catalog_guard.o').read_bytes()))
guest=ELFFile(io.BytesIO((root/'extracted_durak/libil2cpp.so').read_bytes()))
raw=(root/'extracted_durak/libil2cpp.so').read_bytes()
def read(va,n):
    for s in guest.iter_segments():
        if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va and va+n<=s['p_vaddr']+s['p_filesz']:
            off=s['p_offset']+va-s['p_vaddr'];return raw[off:off+n]
    raise ValueError(hex(va))
text=elf.get_section_by_name('.text').data();symbols=elf.get_section_by_name('.symtab')
cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
relocs={r['r_offset']:symbols.get_symbol(r['r_info_sym']).name for r in elf.get_section_by_name('.rela.text').iter_relocations()}
for name,rva in [('table',0xdd65a0),('row',0xdd5ff8),('text',0xd5f3dc)]:
    symbol=symbols.get_symbol_by_name('durak_static_'+name+'_guard')[0]
    start=symbol['st_value'];code=text[start:start+symbol['st_size']];ins=list(cs.disasm(code,start))
    assert [(i.mnemonic,i.op_str) for i in ins[:2]]==[('stp','x0, x1, [sp, #-0x20]!'),('stp','x2, x30, [sp, #0x10]')]
    assert ins[2].mnemonic=='bl' and relocs[ins[2].address]=='durak_static_'+name
    assert ins[3].mnemonic=='cbz' and ins[3].op_str.startswith('x1, ')
    assert [(i.mnemonic,i.op_str) for i in ins[4:7]]==[('ldr','x30, [sp, #0x18]'),('add','sp, sp, #0x20'),('ret','')]
    assert [(i.mnemonic,i.op_str) for i in ins[7:10]]==[('ldp','x0, x1, [sp]'),('ldp','x2, x30, [sp, #0x10]'),('add','sp, sp, #0x20')]
    assert code[-20:-4]==read(rva,16) and ins[-1].mnemonic=='br' and ins[-1].op_str=='x16'
    assert relocs[ins[10].address]==relocs[ins[11].address]=='durak_static_'+name+'_continue'
assert elf.get_section_by_name('.eh_frame') is not None
print('3 ARM64 guards: x0/x1 result, original x0/x1/x2/LR restoration, exact stack prologues and tail continuations verified')
