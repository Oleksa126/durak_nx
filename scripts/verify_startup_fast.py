"""Prove the existing SimpleSQL overwrite flag and its missing-file path."""
import struct
import sys
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile
sys.path.insert(0, 'tools')
from metadata_v39 import Il2CppMetadataV39

meta = Il2CppMetadataV39(Path('extracted_durak/global-metadata.dat').read_bytes())
types = meta.get_type_definitions()
with open('extracted_durak/libil2cpp.so', 'rb') as stream:
    elf = ELFFile(stream)
    rels = {r['r_offset']: r['r_addend'] for r in elf.get_section_by_name('.rela.dyn').iter_relocations()}
    ro = elf.get_section_by_name('.rodata')
    def read(va, size):
        seg = next(s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'
                   and s['p_vaddr'] <= va and va + size <= s['p_vaddr'] + s['p_filesz'])
        stream.seek(seg['p_offset'] + va - seg['p_vaddr'])
        return stream.read(size)
    def resolve(image_name, namespace, class_name, method_name, count):
        image = next(i for i in meta.get_images() if i['name'] == image_name)
        typ = next(t for t in types[image['type_start']:image['type_start'] + image['type_count']]
                   if t['name'] == class_name and t['namespace'] == namespace)
        method = next(m for m in meta.get_methods_for_type(typ)
                      if m['name'] == method_name and m['param_count'] == count)
        name = ro['sh_addr'] + ro.data().index(image_name.encode() + b'\0')
        module = next(k for k, v in rels.items() if v == name)
        assert 1 <= method['rid'] <= struct.unpack_from('<I', read(module, 24), 8)[0]
        return rels[rels[module + 16] + (method['rid'] - 1) * 8], typ, method
    address, typ, method = resolve('SimpleSQL_Runtime.dll', 'SimpleSQL', 'SimpleSQLManager', 'Initialize', 1)
    assert address == 0x12100dc and method['token'] == 0x06000101
    fields = [meta.get_string(struct.unpack_from('<I', meta.data, meta.sections[11][0] + i * 10)[0])
              for i in range(typ['field_start'], typ['field_start'] + typ['field_count'])]
    assert fields == ['_db', 'databaseFile', 'overrideBasePath', 'overridePathMode',
                      'changeWorkingName', 'workingName', 'overwriteIfExists', 'debugTrace', 'databaseCreated']
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    def instruction(va, mnemonic, operands):
        ins = next(cs.disasm(read(va, 4), va))
        assert (ins.mnemonic, ins.op_str) == (mnemonic, operands), (hex(va), ins)
    exists, _, _ = resolve('mscorlib.dll', 'System.IO', 'File', 'Exists', 1)
    delete, _, _ = resolve('mscorlib.dll', 'System.IO', 'File', 'Delete', 1)
    write, _, _ = resolve('mscorlib.dll', 'System.IO', 'File', 'WriteAllBytes', 2)
    instruction(0x1210328, 'bl', f'#{exists:#x}')
    instruction(0x121032c, 'ldrb', 'w8, [x19, #0x48]')
    instruction(0x121033c, 'tbnz', 'w8, #0, #0x1210344')
    instruction(0x1210340, 'tbnz', 'w0, #0, #0x1210390')
    instruction(0x1210344, 'tbz', 'w0, #0, #0x1210354')
    instruction(0x1210350, 'bl', f'#{delete:#x}')
    instruction(0x1210370, 'bl', f'#{write:#x}')
    print('[PASS] SimpleSQL overwriteIfExists: existing DB retained when false; missing DB still copied; File.Exists/Delete/WriteAllBytes targets verified')
