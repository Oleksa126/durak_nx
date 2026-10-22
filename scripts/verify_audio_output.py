"""Verify the Durak-specific OpenSL selection evidence in the original ELF.

Run with pyelftools + capstone available. Does not modify the guest binary.
"""
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

with Path('extracted_durak/libunity.so').open('rb') as stream:
    elf = ELFFile(stream)
    def data(address, length):
        for section in elf.iter_sections():
            start = section['sh_addr']
            if start <= address and address + length <= start + section['sh_size']:
                return section.data()[address-start:address-start+length]
        raise AssertionError(hex(address))
    def words(address, expected):
        assert data(address, len(expected)*4) == struct.pack('<'+'I'*len(expected), *expected), hex(address)
    notes = elf.get_section_by_name('.note.gnu.build-id')
    assert any(n['n_desc'] == 'bcc661ea2046416d' for n in notes.iter_notes())
    assert data(0x13292c, 22).startswith(b'FMOD OpenSL ES Output\0')
    assert data(0x179510, 24).startswith(b'FMOD Audio Track Output\0')
    # Descriptor builders load type constants and store them at +0x78;
    # setOutput compares the requested type against that exact descriptor field.
    assert struct.unpack('<I', data(0x17fae0, 4))[0] == 24
    assert struct.unpack('<I', data(0x181270, 4))[0] == 23
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    expected = {
        0x108e268: ('adrp', 'x8, #0x179000'),
        0x108e26c: ('add', 'x8, x8, #0x510'),
        0x108e270: ('str', 'x8, [x19]'),
        0x108e2a0: ('adrp', 'x10, #0x181000'),
        0x108e2b4: ('ldr', 'd0, [x10, #0x270]'),
        0x108e334: ('str', 'd0, [x19, #0x78]'),
        0x108f4e4: ('adrp', 'x8, #0x132000'),
        0x108f4ec: ('add', 'x8, x8, #0x92c'),
        0x108f500: ('str', 'x8, [x19]'),
        0x108f4f0: ('adrp', 'x10, #0x17f000'),
        0x108f50c: ('ldr', 'd0, [x10, #0xae0]'),
        0x108f59c: ('str', 'd0, [x19, #0x78]'),
        0x108d7d8: ('bl', '#0x108e238'),
        0x108d7f0: ('bl', '#0x108f490'),
        0x108d7e8: ('bl', '#0x101cb54'),
        0x108d800: ('bl', '#0x101cb54'),
        0x10294d4: ('ldr', 'w8, [x1, #0x78]'),
        0x10294d8: ('cmp', 'w8, w9'),
        0x834b54: ('ldr', 'w1, [sp, #0x3c]'),
        0x834b58: ('bl', '#0x1082bb8'),
        0x1082bdc: ('bl', '#0x10293f4'),
        0x1029510: ('bl', '#0x101d414'),
        0x834b04: ('mov', 'w20, #2'),  # NOSOUND branch remains untouched.
    }
    for address, instruction in expected.items():
        actual = next(md.disasm(data(address, 4), address))
        assert (actual.mnemonic, actual.op_str) == instruction, (hex(address), actual.op_str)
    words(0x85e0a4, [0x528002e8, 0xb9000268, 0x14000005, 0x52800328, 0x52800029])
    words(0x108d874, [0x528002e8, 0xb9000268, 0x14000007, 0x528004a0, 0xd65f03c0])
    replacement = next(md.disasm(struct.pack('<I', 0x52800308), 0))
    assert (replacement.mnemonic, replacement.op_str) == ('mov', 'w8, #0x18')
print('PASS: Durak AudioTrack=23 -> OpenSL=24, call chain, fingerprints, NOSOUND preserved')
