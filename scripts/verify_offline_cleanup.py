"""Prove offline cleanup sites against the original metadata/relocations/code.

Run during packaging. Reads only original extracted inputs and patch source.
No user database, executable or packaged asset is modified.
"""
import io
import re
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from metadata_v39 import Il2CppMetadataV39, SEC_FIELDS


def verify():
    meta = Il2CppMetadataV39((ROOT / 'extracted_durak/global-metadata.dat').read_bytes())
    raw = (ROOT / 'extracted_durak/libil2cpp.so').read_bytes()
    elf = ELFFile(io.BytesIO(raw))
    rels = {r['r_offset']: r['r_addend'] for r in elf.get_section_by_name('.rela.dyn').iter_relocations()}
    segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']

    def read(va, n):
        for s in segments:
            if s['p_vaddr'] <= va and va+n <= s['p_vaddr']+s['p_filesz']:
                off = s['p_offset']+va-s['p_vaddr']
                return raw[off:off+n]
        raise ValueError(f'unmapped original RVA {va:#x}')

    ro = elf.get_section_by_name('.rodata')
    name = ro['sh_addr']+ro.data().index(b'Assembly-CSharp.dll\0')
    modules = [k for k, v in rels.items() if v == name]
    assert len(modules) == 1
    module = modules[0]
    method_count = struct.unpack('<I', read(module+8, 4))[0]
    method_ptrs = rels[module+16]
    types = meta.get_type_definitions()
    image = next(i for i in meta.get_images() if i['name'] == 'Assembly-CSharp.dll')
    app = types[image['type_start']:image['type_start']+image['type_count']]

    def method(cls, name, token, rva, params):
        typ = next(t for t in app if t['name'] == cls and not t['namespace'])
        matches = [m for m in meta.get_methods_for_type(typ) if m['name'] == name and
                   [p['type_index'] for p in m['parameters']] == params]
        assert len(matches) == 1
        m = matches[0]
        assert m['token'] == token and m['return_type'] == 21619
        assert 1 <= m['rid'] <= method_count
        assert rels[method_ptrs+(m['rid']-1)*8] == rva
        return m

    entries = [
        ('SceneLoader', 'ShowSpecialOffer', 0x060005fd, 0xd8f8c8, [19805]),
        ('MainMenuController', 'GetADID', 0x060004ae, 0xd6d57c, []),
        ('MainMenuController', 'OnNoAdsPurchase', 0x060004ac, 0xd6cf1c, []),
        ('MainMenuController', 'ShowAlternatePayment', 0x060004b2, 0xd6dac0, []),
        ('MainMenuController', 'buttonPremium', 0x060004b9, 0xd6e280, []),
        ('MainMenuController', 'buyPremium', 0x060004c7, 0xd7032c, [11902]),
        ('PremiumWindowController', 'buyPremium', 0x060004f0, 0xd72ecc, []),
        ('PremiumWindow', 'buyPremium', 0x060005bb, 0xd88680, []),
    ]
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    cs.detail = True

    def instruction(va, mnemonic, operands):
        i = next(cs.disasm(read(va, 4), va))
        assert (i.mnemonic, i.op_str) == (mnemonic, operands), (hex(va), i.mnemonic, i.op_str)

    # Check every cleanup fingerprint in production, including earlier patches.
    source = (ROOT / 'source/static_catalog_patch.c').read_text()
    table = source.split('static const Cleanup cleanup[]={')[1].split('};')[0]
    sites = {}
    for va, words, replacement in re.findall(r'\{(0x[0-9a-f]+),\{([^}]+)\},(0x[0-9a-f]+)\}', table):
        va = int(va, 16)
        assert va not in sites
        words = [int(w, 16) for w in words.split(',')]
        assert len(words) == 4 and read(va, 16) == struct.pack('<4I', *words)
        sites[va] = int(replacement, 16)
    assert set(sites) == {0xd7af2c, 0xd7af84, 0xcf607c, 0xd6efe0, 0xd6f640, 0xd8f718} | {e[3] for e in entries}
    for cls, name, token, rva, params in entries:
        method(cls, name, token, rva, params)
        assert sites[rva] == 0xd65f03c0
        i = next(cs.disasm(struct.pack('<I', sites[rva]), rva))
        assert i.mnemonic == 'ret' and not i.op_str
        # Original entry has not adjusted SP or overwritten LR when RET executes.
        # Hidden MethodInfo and bool/int/string inputs are unused; no return value.

    method('MainMenuController', 'updateUserBlock', 0x060004c3, 0xd6ee7c, [])
    method('SceneLoader', 'SceneLoadingCounter', 0x060005fc, 0xd8f57c, [19805])
    method('SceneLoader', 'ShowDailyReward', 0x060005fe, 0xd904fc, [])
    for va, target in [(0xd6efe0, 0xd6f0c0), (0xd6f640, 0xd6f858), (0xd8f718, 0xd8f8a8)]:
        i = next(cs.disasm(struct.pack('<I', sites[va]), va))
        assert (i.mnemonic, i.op_str) == ('b', '#'+hex(target))
    # MainMenu retains the global pointer needed for all later refreshes.
    instruction(0xd6efd4, 'adrp', 'x22, #0x1bdb000')
    instruction(0xd6efdc, 'ldr', 'x22, [x22, #0x340]')
    instruction(0xd6f0c0, 'ldr', 'x8, [x22]')
    # Date/time locals from the skipped premium block are used ONLY by the
    # removed companion-offer tail, never by retained profile/currency/cup UI.
    retained = list(cs.disasm(read(0xd6f0c0, 0xd6f640-0xd6f0c0), 0xd6f0c0))
    assert not any('[sp, #0x5' in i.op_str for i in retained)
    instruction(0xd6f118, 'ldr', 'x23, [x23, #0xb60]')
    instruction(0xd6f148, 'ldr', 'x21, [x21, #0x7d8]')
    instruction(0xd6f63c, 'bl', '#0x18c50c4')
    instruction(0xd6f858, 'ldr', 'x0, [x19, #0x50]')
    instruction(0xd6f860, 'mov', 'w1, wzr')
    instruction(0xd6f868, 'bl', '#0x17f8328')  # original SetActive(false)
    instruction(0xd6f86c, 'b', '#0xd6f894')
    assert read(0xd6f894, 24) == struct.pack('<6I', 0xa9494ff4, 0xf94033fe, 0xa94857f6, 0xa9475ff8, 0x910283ff, 0xd65f03c0)
    # Only existing-row UPDATE is bypassed. Missing-row initializers still
    # establish original first_run/date data consumed by the daily reward code.
    instruction(0xd8f714, 'cbz', 'x22, #0xd8f7bc')
    instruction(0xd8f730, 'bl', '#0xdb693c')
    instruction(0xd8f770, 'add', 'w8, w9, #1')
    instruction(0xd8f7b4, 'bl', '#0xdd725c')
    instruction(0xd8f838, 'bl', '#0xdd5108')
    instruction(0xd8f8a4, 'bl', '#0xdd5108')
    assert read(0xd8f8a8, 28) == struct.pack('<7I', 0xa9454ff4, 0xf9400bfe, 0xa94457f6, 0xa9435ff8, 0xa94267fa, 0x910183ff, 0xd65f03c0)
    instruction(0xd8f45c, 'bl', '#0xd8f57c')
    instruction(0xd8f470, 'bl', '#0xd8f8c8')
    instruction(0xd8f474, 'bl', '#0xd904fc')  # daily reward/load completion retained

    # Locate the registration independently, rather than trusting a guessed
    # field-offset array. Void/int type kinds and method-spec counts constrain it.
    candidates = []
    for a in sorted(rels):
        v, n = rels.get(a+21619*8), rels.get(a+15979*8)
        if not v or not n:
            continue
        try:
            vk = struct.unpack('<I', read(v+8, 4))[0] >> 16 & 255
            nk = struct.unpack('<I', read(n+8, 4))[0] >> 16 & 255
        except ValueError:
            continue
        if (vk, nk) != (1, 8):
            continue
        for p, target in rels.items():
            if target != a:
                continue
            reg = p-56
            if 21619 < struct.unpack('<Q', read(reg+48, 8))[0] < 100000 and reg+72 in rels and 0 < struct.unpack('<Q', read(reg+64, 8))[0] < 100000:
                candidates.append((a, reg))
    assert len(candidates) == 1
    type_ptrs, reg = candidates[0]
    for index, kind in [(21619, 1), (11902, 2), (15979, 8), (19805, 14)]:
        assert struct.unpack('<I', read(rels[type_ptrs+index*8]+8, 4))[0] >> 16 & 255 == kind

    def literal(slot):
        u = struct.unpack('<Q', read(rels[slot], 8))[0]
        assert u >> 29 == 5 and u & 1
        index = (u & 0x1fffffff) >> 1
        begin, end = struct.unpack_from('<II', meta.data, meta.sections[0][0]+index*4)
        return meta.data[meta.sections[1][0]+begin:meta.sections[1][0]+end].decode('utf8')

    assert literal(0x1bdd650) == 'premium_end'
    assert literal(0x1bde7e8) == 'CHECK PREMIUM: '
    assert literal(0x1bdf6a0) == 'first_run'
    # DailyRewards predicate selects first_run, NOT a scene's opening count or
    # last-scene date. Its constructor/calendar/progress paths remain original.
    helper = [(t, m) for t in app if t['method_count'] for m in meta.get_methods_for_type(t)
              if m['name'] == '<ShowDailyReward>b__23_0']
    assert len(helper) == 1
    assert rels[method_ptrs+(helper[0][1]['rid']-1)*8] == 0xd90e04
    instruction(0xd90e3c, 'ldr', 'x8, [x8, #0x6a0]')
    instruction(0xd90e40, 'ldr', 'x0, [x19, #0x18]')
    instruction(0xd90e50, 'b', '#0xf94dbc')  # string equality with first_run

    def table_argument(slot):
        usage = struct.unpack('<Q', read(rels[slot], 8))[0]
        assert usage >> 29 == 6 and usage & 1
        index = (usage & 0x1fffffff) >> 1
        definition, _, inst = struct.unpack('<iii', read(rels[reg+72]+index*12, 12))
        dm = next(t for t in app if t['name'] == 'DataManager' and not t['namespace'])
        get = next(m for m in meta.get_methods_for_type(dm) if m['name'] == 'GetTableData')
        assert definition == get['method_index'] and inst >= 0
        arg = rels[rels[reg+24]+inst*8]
        assert struct.unpack('<I', read(arg, 4))[0] == 1
        td, flags = struct.unpack('<QI', read(rels[rels[arg+8]], 12))
        assert flags >> 16 & 255 == 18
        return types[td]

    assert table_argument(0x1bdf5c0)['name'] == 'SceneOpeningNumber'
    assert table_argument(0x1bdd6e0)['name'] == 'purchased_companions'
    assert struct.unpack('<Q', read(reg+80, 8))[0] == len(types)
    field_offsets = rels[reg+88]

    def field_offset(typ, name):
        for j in range(typ['field_count']):
            ni = struct.unpack_from('<I', meta.data, meta.sections[SEC_FIELDS][0]+(typ['field_start']+j)*10)[0]
            if meta.get_string(ni) == name:
                return struct.unpack('<I', read(rels[field_offsets+typ['type_index']*8]+j*4, 4))[0]
        raise AssertionError(name)

    mm = next(t for t in app if t['name'] == 'MainMenuController')
    assert field_offset(mm, 'companionButton') == 0x50
    assert field_offset(mm, 'profileRibbon') == 0x98
    scene = table_argument(0x1bdf5c0)
    assert scene['namespace'] == 'MetricsTypes'
    for name, offset in [('scene_name', 0x18), ('openings', 0x20), ('date', 0x28)]:
        assert field_offset(scene, '<'+name+'>k__BackingField') == offset
    # GetADID reports an advertising ID and marks its own sent flag. This is
    # not the user-ID creator or any game-result/progress persistence method.
    assert 'adid' in literal(0x1bde778).lower()
    instruction(0xd6d6c4, 'bl', '#0xd6cbf0')  # GetAndroidAdvertiserId
    instruction(0xd6d82c, 'bl', '#0xd4aa80')  # HTTP request
    instruction(0xd6d854, 'ldr', 'x1, [x23]')  # same sent-flag key
    instruction(0xd6d864, 'bl', '#0xdd6b0c')  # SetVariable<int>
    print('offline cleanup: 14 fingerprints; 8 void entries, 3 branches, metadata/relocations, UI epilogues and first_run reward dependency verified')


if __name__ == '__main__':
    verify()
