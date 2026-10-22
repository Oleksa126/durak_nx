import zipfile
import io
import struct

# Standard Dalvik instruction lengths in 16-bit code units (words)
DALVIK_OP_LEN = {
    0x00: 1, 0x01: 1, 0x02: 2, 0x03: 3, 0x04: 1, 0x05: 2, 0x06: 3, 0x07: 1, 0x08: 2, 0x09: 3,
    0x0a: 1, 0x0b: 1, 0x0c: 1, 0x0d: 1, 0x0e: 1, 0x0f: 1, 0x10: 1, 0x11: 1, 0x12: 1, 0x13: 2,
    0x14: 3, 0x15: 2, 0x16: 2, 0x17: 3, 0x18: 5, 0x19: 2, 0x1a: 2, 0x1b: 3, 0x1c: 2, 0x1d: 1,
    0x1e: 1, 0x1f: 2, 0x20: 2, 0x21: 1, 0x22: 2, 0x23: 2, 0x24: 3, 0x25: 3, 0x26: 3, 0x27: 1,
    0x28: 1, 0x29: 2, 0x2a: 3, 0x2b: 3, 0x2c: 3, 0x2d: 2, 0x2e: 2, 0x2f: 2, 0x30: 2, 0x31: 2,
    0x32: 2, 0x33: 2, 0x34: 2, 0x35: 2, 0x36: 2, 0x37: 2, 0x38: 2, 0x39: 2, 0x3a: 2, 0x3b: 2,
    0x3c: 2, 0x3d: 2, 0x3e: 1, 0x3f: 1, 0x40: 1, 0x41: 1, 0x42: 1, 0x43: 1, 0x44: 2, 0x45: 2,
    0x46: 2, 0x47: 2, 0x48: 2, 0x49: 2, 0x4a: 2, 0x4b: 2, 0x4c: 2, 0x4d: 2, 0x4e: 2, 0x4f: 2,
    0x50: 2, 0x51: 2, 0x52: 2, 0x53: 2, 0x54: 2, 0x55: 2, 0x56: 2, 0x57: 2, 0x58: 2, 0x59: 2,
    0x5a: 2, 0x5b: 2, 0x5c: 2, 0x5d: 2, 0x5e: 2, 0x5f: 2, 0x60: 2, 0x61: 2, 0x62: 2, 0x63: 2,
    0x64: 2, 0x65: 2, 0x66: 2, 0x67: 2, 0x68: 2, 0x69: 2, 0x6a: 2, 0x6b: 2, 0x6c: 2, 0x6d: 2,
    0x6e: 3, 0x6f: 3, 0x70: 3, 0x71: 3, 0x72: 3, 0x74: 3, 0x75: 3, 0x76: 3, 0x77: 3, 0x78: 3,
    0x7b: 1, 0x7c: 1, 0x7d: 1, 0x7e: 1, 0x7f: 1, 0x80: 1, 0x81: 1, 0x82: 1, 0x83: 1, 0x84: 1,
    0x85: 1, 0x86: 1, 0x87: 1, 0x88: 1, 0x89: 1, 0x8a: 1, 0x8b: 1, 0x8c: 1, 0x8d: 1, 0x8e: 1,
    0x8f: 1, 0x90: 2, 0x91: 2, 0x92: 2, 0x93: 2, 0x94: 2, 0x95: 2, 0x96: 2, 0x97: 2, 0x98: 2,
    0x99: 2, 0x9a: 2, 0x9b: 2, 0x9c: 2, 0x9d: 2, 0x9e: 2, 0x9f: 2, 0xa0: 2, 0xa1: 2, 0xa2: 2,
    0xa3: 2, 0xa4: 2, 0xa5: 2, 0xa6: 2, 0xa7: 2, 0xa8: 2, 0xa9: 2, 0xaa: 2, 0xab: 2, 0xac: 2,
    0xad: 2, 0xae: 2, 0xaf: 2, 0xb0: 1, 0xb1: 1, 0xb2: 1, 0xb3: 1, 0xb4: 1, 0xb5: 1, 0xb6: 1,
    0xb7: 1, 0xb8: 1, 0xb9: 1, 0xba: 1, 0xbb: 1, 0xbc: 1, 0xbd: 1, 0xbe: 1, 0xbf: 1, 0xc0: 1,
    0xc1: 1, 0xc2: 1, 0xc3: 1, 0xc4: 1, 0xc5: 1, 0xc6: 1, 0xc7: 1, 0xc8: 1, 0xc9: 1, 0xca: 1,
    0xcb: 1, 0xcc: 1, 0xcd: 1, 0xce: 1, 0xcf: 1, 0xd0: 2, 0xd1: 2, 0xd2: 2, 0xd3: 2, 0xd4: 2,
    0xd5: 2, 0xd6: 2, 0xd7: 2, 0xd8: 2, 0xd9: 2, 0xda: 2, 0xdb: 2, 0xdc: 2, 0xdd: 2, 0xde: 2,
    0xdf: 2, 0xe0: 2, 0xe1: 2, 0xe2: 2, 0xfa: 4, 0xfb: 4
}

def read_uleb(dex_bytes, pos):
    val = 0
    shift = 0
    while True:
        b = dex_bytes[pos]
        pos += 1
        val |= (b & 0x7f) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return val, pos

def disassemble_insns(insns, strings, types, fields, methods):
    lines = []
    pc = 0
    while pc < len(insns):
        op = insns[pc]
        # Fail-closed check: switch or array payload pseudo-opcodes (0x0100, 0x0200, 0x0300)
        if op == 0x00 and pc + 1 < len(insns) and insns[pc + 1] in (0x01, 0x02, 0x03):
            raise ValueError(f"Fail-closed: Unhandled Dalvik payload pseudo-instruction 0x{insns[pc+1]:02x}00 at pc 0x{pc:04x}")

        if op not in DALVIK_OP_LEN:
            raise ValueError(f"Fail-closed: Unknown or unsupported Dalvik opcode 0x{op:02x} at pc 0x{pc:04x}")

        word_len = DALVIK_OP_LEN[op]
        byte_len = word_len * 2
        if pc + byte_len > len(insns):
            raise ValueError(f"Fail-closed: Instruction 0x{op:02x} at pc 0x{pc:04x} exceeds code length {len(insns)}")

        raw = insns[pc : pc + byte_len]
        
        desc = f"op_0x{op:02x}"
        if op == 0x00:
            desc = "nop"
        elif op == 0x0e:
            desc = "return-void"
        elif op == 0x0f:
            desc = f"return v{raw[1]}"
        elif op == 0x11:
            desc = f"return-object v{raw[1]}"
        elif op == 0x0a:
            desc = f"move-result v{raw[1]}"
        elif op == 0x0c:
            desc = f"move-result-object v{raw[1]}"
        elif op == 0x12:
            reg = raw[1] & 0x0f
            val = raw[1] >> 4
            if val >= 8: val -= 16
            desc = f"const/4 v{reg}, #{val}"
        elif op == 0x13:
            reg = raw[1]
            val = struct.unpack_from('<h', raw, 2)[0]
            desc = f"const/16 v{reg}, #{val}"
        elif op == 0x15:
            reg = raw[1]
            val = struct.unpack_from('<h', raw, 2)[0]
            desc = f"const-high16 v{reg}, #{val}0000"
        elif op == 0x14:
            reg = raw[1]
            val = struct.unpack_from('<i', raw, 2)[0]
            desc = f"const v{reg}, #{val}"
        elif op == 0x1a:
            reg = raw[1]
            sidx = struct.unpack_from('<H', raw, 2)[0]
            desc = f"const-string v{reg}, \"{strings[sidx]}\""
        elif op == 0x1b:
            reg = raw[1]
            sidx = struct.unpack_from('<I', raw, 2)[0]
            desc = f"const-string/jumbo v{reg}, \"{strings[sidx]}\""
        elif op in (0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58):
            reg = raw[1] & 0x0f
            obj = (raw[1] >> 4) & 0x0f
            fidx = struct.unpack_from('<H', raw, 2)[0]
            desc = f"iget v{reg}, v{obj}, {fields[fidx][0]}->{fields[fidx][1]}:{fields[fidx][2]}"
        elif op in (0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f):
            reg = raw[1] & 0x0f
            obj = (raw[1] >> 4) & 0x0f
            fidx = struct.unpack_from('<H', raw, 2)[0]
            desc = f"iput v{reg}, v{obj}, {fields[fidx][0]}->{fields[fidx][1]}:{fields[fidx][2]}"
        elif op in (0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66):
            reg = raw[1]
            fidx = struct.unpack_from('<H', raw, 2)[0]
            desc = f"sget v{reg}, {fields[fidx][0]}->{fields[fidx][1]}:{fields[fidx][2]}"
        elif op in (0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d):
            reg = raw[1]
            fidx = struct.unpack_from('<H', raw, 2)[0]
            desc = f"sput v{reg}, {fields[fidx][0]}->{fields[fidx][1]}:{fields[fidx][2]}"
        elif op in (0x6e, 0x6f, 0x70, 0x71, 0x72):
            count = (raw[1] >> 4) & 0x0f
            midx = struct.unpack_from('<H', raw, 2)[0]
            c_reg = raw[4] & 0x0f
            d_reg = (raw[4] >> 4) & 0x0f
            e_reg = raw[5] & 0x0f
            f_reg = (raw[5] >> 4) & 0x0f
            g_reg = raw[1] & 0x0f
            regs = [c_reg, d_reg, e_reg, f_reg, g_reg][:count]
            regs_s = ', '.join([f"v{r}" for r in regs])
            kind = {0x6e: "invoke-virtual", 0x6f: "invoke-super", 0x70: "invoke-direct", 0x71: "invoke-static", 0x72: "invoke-interface"}[op]
            desc = f"{kind} {{{regs_s}}}, {methods[midx][0]}->{methods[midx][1]}{methods[midx][2]}"
        elif op in (0x74, 0x75, 0x76, 0x77, 0x78):
            count = raw[1]
            midx = struct.unpack_from('<H', raw, 2)[0]
            first_r = struct.unpack_from('<H', raw, 4)[0]
            kind = {0x74: "invoke-virtual/range", 0x75: "invoke-super/range", 0x76: "invoke-direct/range", 0x77: "invoke-static/range", 0x78: "invoke-interface/range"}[op]
            desc = f"{kind} {{v{first_r}..v{first_r+count-1}}}, {methods[midx][0]}->{methods[midx][1]}{methods[midx][2]}"
        elif op in (0x28, 0x29, 0x2a):
            desc = f"goto (target offset)"
        elif op in (0x32, 0x33, 0x34, 0x35, 0x36, 0x37):
            va = raw[1] & 0x0f
            vb = (raw[1] >> 4) & 0x0f
            desc = f"if-test v{va}, v{vb}"
        elif op in (0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d):
            va = raw[1]
            desc = f"if-testz v{va}"
        elif op == 0x22:
            reg = raw[1]
            tidx = struct.unpack_from('<H', raw, 2)[0]
            desc = f"new-instance v{reg}, {types[tidx]}"

        lines.append((pc, desc))
        pc += byte_len
    return lines

def main():
    z = zipfile.ZipFile('Durak_25.0.apks')
    bz = zipfile.ZipFile(io.BytesIO(z.read('base.apk')))
    dex_bytes = bz.read('classes5.dex')

    string_ids_size = struct.unpack_from('<I', dex_bytes, 56)[0]
    string_ids_off = struct.unpack_from('<I', dex_bytes, 60)[0]
    strings = []
    for i in range(string_ids_size):
        str_off = struct.unpack_from('<I', dex_bytes, string_ids_off + i * 4)[0]
        pos = str_off; length = 0; shift = 0
        while True:
            b = dex_bytes[pos]; pos += 1; length |= (b & 0x7f) << shift
            if (b & 0x80) == 0: break
            shift += 7
        s_end = dex_bytes.find(b'\x00', pos)
        strings.append(dex_bytes[pos:s_end].decode('utf-8', 'replace'))

    type_ids_size = struct.unpack_from('<I', dex_bytes, 64)[0]
    type_ids_off = struct.unpack_from('<I', dex_bytes, 68)[0]
    types = [strings[struct.unpack_from('<I', dex_bytes, type_ids_off + i * 4)[0]] for i in range(type_ids_size)]

    proto_ids_size = struct.unpack_from('<I', dex_bytes, 72)[0]
    proto_ids_off = struct.unpack_from('<I', dex_bytes, 76)[0]
    protos = []
    for i in range(proto_ids_size):
        shorty_idx, return_type_idx, parameters_off = struct.unpack_from('<III', dex_bytes, proto_ids_off + i * 12)
        ret_t = types[return_type_idx]
        param_types = []
        if parameters_off != 0:
            param_size = struct.unpack_from('<I', dex_bytes, parameters_off)[0]
            for p in range(param_size):
                type_idx = struct.unpack_from('<H', dex_bytes, parameters_off + 4 + p * 2)[0]
                param_types.append(types[type_idx])
        sig = '(' + ''.join(param_types) + ')' + ret_t
        protos.append(sig)

    method_ids_size = struct.unpack_from('<I', dex_bytes, 88)[0]
    method_ids_off = struct.unpack_from('<I', dex_bytes, 92)[0]
    methods = []
    for i in range(method_ids_size):
        class_idx, proto_idx, name_idx = struct.unpack_from('<HHI', dex_bytes, method_ids_off + i * 8)
        methods.append((types[class_idx], strings[name_idx], protos[proto_idx]))

    field_ids_size = struct.unpack_from('<I', dex_bytes, 80)[0]
    field_ids_off = struct.unpack_from('<I', dex_bytes, 84)[0]
    fields = []
    for i in range(field_ids_size):
        class_idx, type_idx, name_idx = struct.unpack_from('<HHI', dex_bytes, field_ids_off + i * 8)
        fields.append((types[class_idx], strings[name_idx], types[type_idx]))

    class_defs_size = struct.unpack_from('<I', dex_bytes, 96)[0]
    class_defs_off = struct.unpack_from('<I', dex_bytes, 100)[0]

    target_methods = [
        ('Lcom/unity3d/player/UnityPlayer;', 'initialize', '(Landroid/widget/FrameLayout;)V'),
        ('Lcom/unity3d/player/UnityPlayer;', 'initialize', '(Landroid/widget/FrameLayout;Ljava/lang/String;)V'),
        ('Lcom/unity3d/player/UnityPlayerForActivityOrService;', '<init>', '(Landroid/content/Context;Lcom/unity3d/player/IUnityPlayerLifecycleEvents;)V'),
        ('Lcom/unity3d/player/UnityPlayerForActivityOrService;', '<init>', '(Landroid/content/Context;Lcom/unity3d/player/IUnityPlayerLifecycleEvents;Ljava/lang/String;Lcom/unity3d/player/a/d;)V'),
    ]

    for c_idx in range(class_defs_size):
        off = class_defs_off + c_idx * 32
        class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off = struct.unpack_from('<IIIIIIII', dex_bytes, off)
        if class_data_off == 0: continue
        pos = class_data_off
        static_fields_size, pos = read_uleb(dex_bytes, pos); instance_fields_size, pos = read_uleb(dex_bytes, pos)
        direct_methods_size, pos = read_uleb(dex_bytes, pos); virtual_methods_size, pos = read_uleb(dex_bytes, pos)
        for _ in range(static_fields_size): _, pos = read_uleb(dex_bytes, pos); _, pos = read_uleb(dex_bytes, pos)
        for _ in range(instance_fields_size): _, pos = read_uleb(dex_bytes, pos); _, pos = read_uleb(dex_bytes, pos)
        
        all_m = []
        m_id = 0
        for _ in range(direct_methods_size):
            m_diff, pos = read_uleb(dex_bytes, pos); m_id += m_diff
            m_flags, pos = read_uleb(dex_bytes, pos); code_off, pos = read_uleb(dex_bytes, pos)
            all_m.append((m_id, code_off))
        m_id = 0
        for _ in range(virtual_methods_size):
            m_diff, pos = read_uleb(dex_bytes, pos); m_id += m_diff
            m_flags, pos = read_uleb(dex_bytes, pos); code_off, pos = read_uleb(dex_bytes, pos)
            all_m.append((m_id, code_off))
            
        for mid, code_off in all_m:
            if code_off == 0: continue
            entry = methods[mid]
            for tgt in target_methods:
                if entry[0] == tgt[0] and entry[1] == tgt[1] and entry[2] == tgt[2]:
                    registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size = struct.unpack_from('<HHHHII', dex_bytes, code_off)
                    insns = dex_bytes[code_off + 16 : code_off + 16 + insns_size * 2]
                    first_arg_reg = registers_size - ins_size
                    print(f"\n================================================================================")
                    print(f"METHOD: {entry[0]}->{entry[1]}{entry[2]}")
                    print(f"CODE OFFSET: 0x{code_off:x}, INSNS: {insns_size} words, REGISTERS: total={registers_size}, in={ins_size} (args starting at v{first_arg_reg}), outs={outs_size}")
                    print(f"================================================================================")
                    lines = disassemble_insns(insns, strings, types, fields, methods)
                    for pc, desc in lines:
                        # Print instructions of interest or full snippet
                        if 'initJni' in desc or 'initialize' in desc or 'const-string' in desc or 'mContext' in desc:
                            print(f"  [pc 0x{pc:04x}] {desc}")
                        elif tgt[1] == 'initialize' and tgt[2].endswith('String;)V') and pc in range(0x130, 0x148):
                            print(f"  [pc 0x{pc:04x}] {desc}")
                        elif tgt[1] == 'initialize' and not tgt[2].endswith('String;)V'):
                            print(f"  [pc 0x{pc:04x}] {desc}")
                        elif tgt[1] == '<init>' and tgt[2] == '(Landroid/content/Context;Lcom/unity3d/player/IUnityPlayerLifecycleEvents;)V':
                            print(f"  [pc 0x{pc:04x}] {desc}")

if __name__ == '__main__':
    main()
