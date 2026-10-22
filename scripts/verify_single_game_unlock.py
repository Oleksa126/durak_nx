"""Verify unlock sites against target ELF, metadata and ARM64 disassembly.

Requires pyelftools and capstone; run from the repository root.
"""
import re
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

sys.path.insert(0, 'tools')
from metadata_v39 import Il2CppMetadataV39

meta = Il2CppMetadataV39(Path('extracted_durak/global-metadata.dat').read_bytes())
with open('extracted_durak/libil2cpp.so', 'rb') as stream:
    elf = ELFFile(stream)
    rels = {r['r_offset']: r['r_addend'] for r in
            elf.get_section_by_name('.rela.dyn').iter_relocations()}
    ro = elf.get_section_by_name('.rodata')
    name = ro['sh_addr'] + ro.data().index(b'Assembly-CSharp.dll\0')
    module = next(k for k, v in rels.items() if v == name)

    def read_va(va, size):
        for seg in elf.iter_segments():
            if seg['p_type'] == 'PT_LOAD' and seg['p_vaddr'] <= va and va + size <= seg['p_vaddr'] + seg['p_filesz']:
                stream.seek(seg['p_offset'] + va - seg['p_vaddr'])
                return stream.read(size)
        raise ValueError(f'Unmapped RVA {va:x}')

    image = next(i for i in meta.get_images() if i['name'] == 'Assembly-CSharp.dll')
    typ = next(t for t in meta.get_type_definitions()[image['type_start']:image['type_start'] + image['type_count']]
               if t['name'] == 'SinglePlayerSelect')
    method = next(m for m in meta.get_methods_for_type(typ) if m['name'] == 'Start')
    count = struct.unpack_from('<I', read_va(module, 24), 8)[0]
    assert 1 <= method['rid'] <= count
    start = rels[rels[module + 16] + (method['rid'] - 1) * 8]
    assert start == 0xd7a518 and method['token'] == 0x0600052b
    table = Path('include/region_patch.h').read_text().split('DURAK_SINGLE_GAME_UNLOCK[] = {')[1].split('};')[0]
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    sites = re.findall(r'\{(0x[0-9a-f]+), \{([^}]+)\}, (0x[0-9a-f]+)\}', table)
    assert len(sites) == 3
    for address, words, replacement in sites:
        address = int(address, 16)
        expected = [int(w.strip(), 16) for w in words.split(',')]
        actual = read_va(address, 20)
        assert actual == struct.pack('<5I', *expected)
        assert start < address < 0xd7abe4
        decoded = list(cs.disasm(actual, address))
        assert decoded[1].mnemonic == 'cset' and decoded[1].op_str.endswith(', gt')
        assert decoded[4].mnemonic == 'strb' and decoded[4].op_str.endswith('[x24, #0x24]')
        new = next(cs.disasm(struct.pack('<I', int(replacement, 16)), address + 4))
        assert new.mnemonic == 'mov' and new.op_str.endswith(', wzr')
        assert new.op_str.split(',')[0] == decoded[1].op_str.split(',')[0]
        print(f'{address+4:#x}: {decoded[1].mnemonic} {decoded[1].op_str} -> {new.mnemonic} {new.op_str}; isLocked store verified')
    print(f'SinglePlayerSelect.Start token={method["token"]:#x} RVA={start:#x}; 3/3 sites verified')
    rating = next(t for t in meta.get_type_definitions()[image['type_start']:image['type_start'] + image['type_count']]
                  if t['name'] == 'WindowsInvoker')
    method = next(m for m in meta.get_methods_for_type(rating) if m['name'] == 'InvokeRateWnd')
    address = rels[rels[module + 16] + (method['rid'] - 1) * 8]
    assert address == 0xd8e8ac and method['param_count'] == 0 and method['return_type'] == 21619
    header = Path('include/region_patch.h').read_text()
    words = header.split('DURAK_RATE_PROMPT_CONTEXT[] = {')[1].split('};')[0]
    expected = [int(w.strip(), 16) for w in words.strip().split(',')]
    assert read_va(address, 20) == struct.pack('<5I', *expected)
    print(f'WindowsInvoker.InvokeRateWnd token={method["token"]:#x}, RVA={address:#x}: entry fingerprint verified')
    method = next(m for m in meta.get_methods_for_type(rating) if m['name'] == 'InvokeFreeKeyWnd')
    address = rels[rels[module + 16] + (method['rid'] - 1) * 8]
    assert address == 0xd8e9a0 and method['token'] == 0x060005ea
    assert method['param_count'] == 0 and method['return_type'] == 21619
    words = header.split('DURAK_FREE_KEY_PROMPT_CONTEXT[] = {')[1].split('};')[0]
    expected = [int(w.strip(), 16) for w in words.strip().split(',')]
    assert read_va(address, 20) == struct.pack('<5I', *expected)
    print(f'WindowsInvoker.InvokeFreeKeyWnd token={method["token"]:#x}, RVA={address:#x}: void ABI and entry verified')
    draft = next(t for t in meta.get_type_definitions()[image['type_start']:image['type_start'] + image['type_count']]
                 if t['name'] == 'DRAFT')
    method = next(m for m in meta.get_methods_for_type(draft) if m['name'] == 'ShowPremimBannerWnd')
    assert method['token'] == 0x0600000a and method['return_type'] == 21619
    assert method['param_count'] == 1 and method['parameters'][0]['name'] == 'index'
    assert rels[rels[module + 16] + (method['rid'] - 1) * 8] == 0xcf607c
    words = header.split('DURAK_PREMIUM_OFFER_CONTEXT[] = {')[1].split('};')[0]
    expected = [int(w.strip(), 16) for w in words.strip().split(',')]
    assert read_va(0xcf6120, 48) == struct.pack('<12I', *expected)
    assert next(cs.disasm(read_va(0xcf6090, 4), 0xcf6090)).op_str == 'w19, w1'
    assert next(cs.disasm(read_va(0xcf6124, 4), 0xcf6124)).op_str == 'w1, #3'
    # Metadata usage: literal index encoded (5 << 29) | (index << 1) | 1.
    usage = struct.unpack('<Q', read_va(rels[0x1bdb310], 8))[0]
    assert usage == (5 << 29) | (6306 << 1) | 1
    literal_offsets = meta.sections[0][0]
    begin, end = struct.unpack_from('<II', meta.data, literal_offsets + 6306 * 4)
    literal_data = meta.sections[1][0]
    assert meta.data[literal_data + begin:literal_data + end] == b'PremiumOfferWnd'
    assert next(cs.disasm(read_va(0xcf6158, 4), 0xcf6158)).op_str == 'x9, [x9, #0x310]'
    assert next(cs.disasm(read_va(0xcf6160, 4), 0xcf6160)).op_str == 'x9, [x0, #0x28]'
    assert read_va(0xcf6234, 16) == struct.pack('<4I', 0xa9424ff4, 0xa94157fe, 0x9100c3ff, 0xd65f03c0)
    replacement = list(cs.disasm(struct.pack('<I', 0x7100067f), 0xcf613c))[0]
    assert replacement.mnemonic == 'cmp' and replacement.op_str == 'w19, #1'
    branch = next(cs.disasm(struct.pack('<I', 0x54000740), 0xcf614c))
    assert branch.mnemonic == 'b.eq' and branch.op_str == '#0xcf6234'
    print('DRAFT.ShowPremimBannerWnd: index 1 = PremiumOfferWnd; allocation=3; balanced epilogue verified')
    method = next(m for m in meta.get_methods_for_type(typ) if m['name'] == 'OnEnable')
    assert method['token'] == 0x0600052c and method['param_count'] == 0
    assert method['return_type'] == 21619
    assert rels[rels[module + 16] + (method['rid'] - 1) * 8] == 0xd7ae44
    words = header.split('DURAK_SINGLE_PREMIUM_CONTEXT[] = {')[1].split('};')[0]
    expected = [int(w.strip(), 16) for w in words.strip().split(',')]
    assert read_va(0xd7b0b0, 48) == struct.pack('<12I', *expected)
    usage = struct.unpack('<Q', read_va(rels[0x1bdec08], 8))[0]
    assert usage == (5 << 29) | (8996 << 1) | 1
    begin, end = struct.unpack_from('<II', meta.data, literal_offsets + 8996 * 4)
    assert meta.data[literal_data + begin:literal_data + end] == b'Windows/PremiumWindows/PremiumOfferWnd'
    assert next(cs.disasm(read_va(0xd7b0cc, 4), 0xd7b0cc)).op_str == 'x8, [x8, #0xc08]'
    assert next(cs.disasm(read_va(0xd7b0dc, 4), 0xd7b0dc)).op_str == '#0xe08d04'
    assert next(cs.disasm(read_va(0xd7b164, 4), 0xd7b164)).op_str == '#0xd84ae4'  # Window.Open
    old = next(cs.disasm(read_va(0xd7b0c0, 4), 0xd7b0c0))
    new = next(cs.disasm(struct.pack('<I', 0x1400002a), 0xd7b0c0))
    assert old.mnemonic == 'b.ge' and new.mnemonic == 'b'
    assert old.op_str == new.op_str == '#0xd7b168'
    assert next(cs.disasm(read_va(0xd7b1b8, 4), 0xd7b1b8)).op_str == '#0xd78870'  # showTab
    assert read_va(0xd7b1bc, 20) == struct.pack('<5I', 0xa9444ff4, 0xf94013fe, 0xa94357f6, 0x910143ff, 0xd65f03c0)
    print('SinglePlayerSelect.OnEnable: direct PremiumOfferWnd skipped before instantiation; showTab and epilogue retained')
