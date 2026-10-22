"""Compile original immutable catalogs; verify the managed boundary against ELF.

No user database is read or changed. --check rejects stale generated code.
"""
import argparse
import io
import json
import sqlite3
import struct
import sys
from pathlib import Path

import UnityPy
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from metadata_v39 import Il2CppMetadataV39, SEC_FIELDS


def generate():
    meta = Il2CppMetadataV39((ROOT / 'extracted_durak/global-metadata.dat').read_bytes())
    raw = (ROOT / 'extracted_durak/libil2cpp.so').read_bytes()
    elf = ELFFile(io.BytesIO(raw))
    rels = {r['r_offset']: r['r_addend'] for r in elf.get_section_by_name('.rela.dyn').iter_relocations()}
    def read(va, n):
        for seg in elf.iter_segments():
            if seg['p_type'] == 'PT_LOAD' and seg['p_vaddr'] <= va and va+n <= seg['p_vaddr']+seg['p_filesz']:
                off = seg['p_offset']+va-seg['p_vaddr']
                return raw[off:off+n]
        raise ValueError(hex(va))
    ro = elf.get_section_by_name('.rodata')
    module = next(k for k,v in rels.items() if v == ro['sh_addr']+ro.data().index(b'Assembly-CSharp.dll\0'))
    mp = rels[module+16]
    types = meta.get_type_definitions()
    image = next(i for i in meta.get_images() if i['name'] == 'Assembly-CSharp.dll')
    app = types[image['type_start']:image['type_start']+image['type_count']]
    def method(cls, name, params):
        typ = next(t for t in app if t['name'] == cls and not t['namespace'])
        return next(m for m in meta.get_methods_for_type(typ) if m['name'] == name and [p['type_index'] for p in m['parameters']] == params)
    key = method('LocalizationManager', 'GetText', [19805])
    assert key['token'] == 0x0600043e and key['return_type'] == 19805
    assert rels[mp+(key['rid']-1)*8] == 0xd5f3dc
    dm = next(t for t in app if t['name'] == 'DataManager')
    table = next(m for m in meta.get_methods_for_type(dm) if m['name'] == 'GetTableData')
    row = method('DataManager', 'GetRowData', [15979])
    # Discover type registration via its metadata-registration pointer pair.
    candidates = []
    for address in sorted(rels):
        v = rels.get(address+21619*8); i = rels.get(address+15979*8)
        if not v or not i: continue
        if not all(any(s['p_type']=='PT_LOAD' and s['p_vaddr']<=a and a+12<=s['p_vaddr']+s['p_filesz'] for s in elf.iter_segments()) for a in (v,i)):continue
        if struct.unpack('<I',read(v+8,4))[0] >> 16 & 255 == 1 and struct.unpack('<I',read(i+8,4))[0] >> 16 & 255 == 8:
            parents = [p for p,target in rels.items() if target == address]
            for p in parents:
                reg=p-56
                if 21619 < struct.unpack('<Q',read(reg+48,8))[0] < 100000 and reg+72 in rels and 0 < struct.unpack('<Q',read(reg+64,8))[0] < 100000:
                    candidates.append((address,reg))
    assert len(candidates) == 1, candidates
    type_ptrs,reg = candidates[0]
    specs=rels[reg+72]
    spec_count=struct.unpack('<Q',read(reg+64,8))[0]
    def usage_method(slot):
        usage=struct.unpack('<Q',read(rels[slot],8))[0]
        assert usage >> 29 == 6 and usage & 1
        index=(usage & 0x1fffffff) >> 1
        assert index < spec_count
        return struct.unpack('<iii',read(specs+index*12,12))[0]
    assert usage_method(0x1bde198) == table['method_index']
    cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
    # Unity 6 uses pointer-sized opaque GC slots. Do not import the historical
    # uint32_t handle ABI: it discards the block address on this ARM64 target.
    api_symbols={s.name:s['st_value'] for s in elf.get_section_by_name('.dynsym').iter_symbols()}
    for symbol,export,body in [('il2cpp_gchandle_new',0xbeb5b8,0xbe5690),('il2cpp_gchandle_get_target',0xbeb5f0,0xbe5a6c),('il2cpp_gchandle_free',0xbeb638,0xbe5be8)]:
        assert api_symbols[symbol]==export
        ins=next(cs.disasm(read(export,4),export));assert (ins.mnemonic,ins.op_str)==('b','#'+hex(body))
    for va,mnemonic,operands in [(0xbe595c,'csel','x0, x9, x21, lo'),(0xbe5a80,'and','x23, x0, #0xffffffffffffe000'),(0xbe5a84,'ldrb','w8, [x23, #0x20]'),(0xbe5c00,'and','x22, x0, #0xffffffffffffe000'),(0xbe5c04,'ldrb','w8, [x22, #0x20]')]:
        ins=next(cs.disasm(read(va,4),va));assert (ins.mnemonic,ins.op_str)==(mnemonic,operands)
    # This target's reference setter uses the object itself, not void** data.
    # Export -> Field::SetValue -> SetValueRaw(dereference=false); STRING and
    # SZARRAY jump to the reference store. Scalar cells still use value bytes.
    assert api_symbols['il2cpp_field_set_value']==0xbeb52c
    for va,mnemonic,operands in [(0xbeb52c,'b','#0xc40b1c'),(0xc40b24,'mov','w3, wzr'),(0xc40b30,'b','#0xc4047c'),(0xc4048c,'mov','x20, x2'),(0xc40498,'mov','w21, w3'),(0xc4050c,'tbz','w21, #0, #0xc40514'),(0xc40514,'mov','x0, x19'),(0xc40518,'mov','x1, x20'),(0xc40528,'b','#0xbe6a14'),(0xbe6a14,'str','x1, [x0]')]:
        ins=next(cs.disasm(read(va,4),va));assert (ins.mnemonic,ins.op_str)==(mnemonic,operands)
    for kind in (14,29):assert 0xc404c8+read(0x768d94+kind-2,1)[0]*4==0xc4050c
    key_code=list(cs.disasm(read(0xd5f3dc,0x2a0),0xd5f3dc))
    assert any(i.address == 0xd5f500 and i.mnemonic == 'bl' and i.op_str == '#0xdd65a0' for i in key_code)
    # Generic GetText<T>(id) calls GetRowData<T>(id) with its resolved MethodInfo.
    # Its RGCTX method spec is proven through the generic-method table below.
    assert any(i.mnemonic == 'bl' and i.op_str == '#0xdd5ff8' for i in cs.disasm(read(0xdfd2d8,0x324),0xdfd2d8))
    gtable=rels[reg+40]; gn=struct.unpack('<Q',read(reg+32,8))[0]
    generic_pointer_arrays=[]
    for off,target in rels.items():
        if target == 0xdd65a0:
            # Code-registration pair for generic method pointer array is found
            # by matching both known shared bodies at their registration indices.
            generic_pointer_arrays.append(off)
    generic_entries=[]
    for i in range(gn):
        spec, pointer_index, invoker, adjustor=struct.unpack('<4i',read(gtable+i*16,16))
        if spec < 0 or spec >= spec_count: continue
        definition=struct.unpack('<i',read(specs+spec*12,4))[0]
        if definition not in (table['method_index'],row['method_index']):continue
        generic_entries.append((definition,pointer_index))
    first=next(pi for definition,pi in generic_entries if definition==table['method_index'])
    bases=[entry-first*8 for entry in generic_pointer_arrays]
    bases=[base for base in bases if all(rels.get(base+pi*8)==(0xdd65a0 if definition==table['method_index'] else 0xdd5ff8) for definition,pi in generic_entries)]
    assert len(bases)==1,bases
    proven={'base':bases[0]}
    found={}
    for i in range(gn):
        spec,pi,_,_=struct.unpack('<4i',read(gtable+i*16,16))
        if spec < 0 or spec >= spec_count:continue
        definition=struct.unpack('<i',read(specs+spec*12,4))[0]
        if definition in (table['method_index'],row['method_index']):
            found.setdefault(definition,set()).add(rels.get(proven['base']+pi*8,0))
    assert 0xdd65a0 in found[table['method_index']] and 0xdd5ff8 in found[row['method_index']], found
    def type_kind(index):
        return struct.unpack('<I',read(rels[type_ptrs+index*8]+8,4))[0] >> 16 & 255
    def fields(typ):
        result={}
        # v39 packs byval/declaring/parent/element as four 16-bit indices.
        parent_index=struct.unpack_from('<H',meta.data,meta.sections[19][0]+typ['type_index']*76+12)[0]
        if parent_index != 0xffff:
            ptr=rels[type_ptrs+parent_index*8]
            parent,flags=struct.unpack('<QI',read(ptr,12))
            if flags >> 16 & 255 in (0x11,0x12):result.update(fields(types[parent]))
        foff=meta.sections[SEC_FIELDS][0]
        for i in range(typ['field_start'],typ['field_start']+typ['field_count']):
            name_index,field_type=struct.unpack_from('<IH',meta.data,foff+i*10)
            result[meta.get_string(name_index)]=(type_kind(field_type),field_type)
        return result
    def cstr(s):
        if s is None:return 'NULL'
        s=str(s)  # sqlite3_column_text converts numeric SQLite storage to text.
        return '"'+''.join(chr(b) if 32<=b<127 and b not in (34,92) else '\\%03o'%b for b in s.encode('utf8'))+'"'
    out=['/* Generated from original packaged dict/l10n; do not edit. */']
    # Every supported row ctor tail-calls a verified, side-effect-free base ctor.
    assert read(0xd472f4,8)==struct.pack('<2I',0xaa1f03e1,0x140f983b)
    assert read(0xd6c9f0,8)==struct.pack('<2I',0xaa1f03e1,0x17ff6a40)
    assert next(cs.disasm(read(0x112d3e4,4),0x112d3e4)).mnemonic=='ret'
    # Cleanup skips exactly the marketing increment and expiry/banner block.
    expected_cleanup={0xd7af2c:(0x90007335,0xaa1403e0,0xaa1f03e2,0xf94602b5),0xd7af84:(0xf94002c8,0xf9405d08,0xf9400108,0xb4001208),0xcf607c:(0xd100c3ff,0xa90157fe,0xa9024ff4,0x90008734)}
    for va,words in expected_cleanup.items():assert read(va,16)==struct.pack('<4I',*words)
    for va,word,target in [(0xd7af2c,0x14000012,0xd7af74),(0xd7af84,0x14000079,0xd7b168)]:
        ins=next(cs.disasm(struct.pack('<I',word),va)); assert ins.mnemonic=='b' and ins.op_str=='#'+hex(target)
    assert next(cs.disasm(read(0xd7af78,4),0xd7af78)).op_str=='#0xd79430'
    assert next(cs.disasm(read(0xd7af80,4),0xd7af80)).op_str=='#0xd78cf0'
    assert next(cs.disasm(read(0xd7b1b8,4),0xd7b1b8)).op_str=='#0xd78870'
    for name,rva in [('TABLE',0xdd65a0),('ROW',0xdd5ff8),('TEXT',0xd5f3dc)]:
        first=list(cs.disasm(read(rva,16),rva))
        assert len(first)==4 and all(i.mnemonic in ('sub','str','stp') for i in first)
        out.append('#define DURAK_STATIC_%s_RVA 0x%x'%(name,rva))
        out.append('static const uint32_t catalog_%s_fingerprint[] = {%s};'%(name.lower(),','.join(hex(w) for w in struct.unpack('<8I',read(rva,32)))))
    assert read(0xd6bde8,8)==struct.pack('<2I',0xb9405c00,0xd65f03c0)
    report=[]; tables=[]
    env=UnityPy.load(str(ROOT / 'extracted_durak/sdmc/switch/durak_nx/game/assets/bin/Data/data.unity3d'))
    for ob in env.objects:
        if ob.type.name!='TextAsset':continue
        asset=ob.read()
        if asset.m_Name not in ('dict','l10n'):continue
        ns='DictTypes' if asset.m_Name=='dict' else 'L10nTypes'
        db=sqlite3.connect(':memory:');db.deserialize(asset.m_Script.encode('utf8','surrogateescape'))
        existing={r[0] for r in db.execute("select name from sqlite_master where type='table'")}
        for typ in sorted((t for t in app if t['namespace']==ns and t['name'] in existing),key=lambda t:t['name']):
            ctor=next(m for m in meta.get_methods_for_type(typ) if m['name']=='.ctor')
            addr=rels[mp+(ctor['rid']-1)*8]
            instructions=list(cs.disasm(read(addr,8),addr))
            assert [(i.mnemonic,i.op_str) for i in instructions]==[('mov','x1, xzr'),('b','#'+hex(0xd6c9f0 if ns=='L10nTypes' else 0xd472f4))]
            name=typ['name'];cols=[r[1] for r in db.execute('pragma table_info("'+name+'")')]
            rows=db.execute('select * from "'+name+'" order by id').fetchall()
            assert cols[0]=='id'
            if ns=='DictTypes' and name=='companions':
                # User explicitly removes premium/commerce gates. Identity,
                # art, names and the player's selection/progress stay original.
                rows=[tuple(0 if col in ('price','ispremium','specialofferid') else value for col,value in zip(cols,row_values)) for row_values in rows]
            fs=fields(typ); bindings=[]
            for col in cols:
                field='<'+col+'>k__BackingField'
                assert field in fs,(ns,name,col,fs)
                kind,_=fs[field]
                assert kind in (8,12,14),(ns,name,col,kind)
                bindings.append((field,kind))
            idx=len(tables)
            out.append('static const DurakStaticColumn catalog_cols_%d[] = {'%idx)
            out.extend('{%s,%d},'%(cstr(f),k) for f,k in bindings);out.append('};')
            out.append('static const DurakStaticCell catalog_rows_%d[] = {'%idx)
            for row_values in rows:
                for value,(_,kind) in zip(row_values,bindings):
                    if kind==14:out.append('{.s=%s},'%cstr(value))
                    elif kind==8:out.append('{.i=%d},'%int(value or 0))
                    else:out.append('{.f=%sf},'%repr(float(value or 0)))
            out.append('};')
            tables.append('{%s,%s,%d,%d,catalog_cols_%d,catalog_rows_%d}'%(cstr(ns),cstr(name),len(rows),len(cols),idx,idx))
            report.append({'namespace':ns,'table':name,'rows':len(rows),'columns':cols})
    out.append('static const DurakStaticTable catalog_tables[] = {');out.extend(t+',' for t in tables);out.append('};')
    out.append('#define DURAK_STATIC_TABLE_COUNT (sizeof(catalog_tables)/sizeof(catalog_tables[0]))')
    return '\n'.join(out)+'\n',report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');args=p.parse_args()
    content,report=generate();dest=ROOT/'include/static_catalog_data.h'
    if args.check:assert dest.read_text(encoding='utf8')==content,'stale static catalog data'
    else:dest.write_text(content,encoding='utf8')
    print(json.dumps({'tables':len(report),'rows':sum(t['rows'] for t in report),'managed_boundaries':'metadata + method specs + generic registration + call graph verified','gc_handle_abi':'64-bit X0 slot return/arguments and block dereferences verified','reference_setter':'direct object, dereference=false, STRING/SZARRAY stores verified'},separators=(',',':')))
