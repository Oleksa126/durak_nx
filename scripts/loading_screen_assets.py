"""Add presentation-only loading canvases using existing Durak UI resources."""
import copy
import struct


def add_loading_screens(original):
    added = {}
    source = next(o.assets_file for o in original.values() if o.assets_file.name == 'level3')
    for scene in ('level0', 'level1'):
        target = next(o.assets_file for o in original.values() if o.assets_file.name == scene)
        ids = {52: 10001, 449: 10002, 396: 10003, 706: 10004,
               6: 10005, 403: 10006, 221: 10007, 650: 10008,
               46: 10009, 443: 10010, 255: 10011, 619: 10012}
        assert not set(range(10001, 10017)) & target.objects.keys()

        def external(file_id):
            if not file_id:
                return 0
            ref = source.externals[file_id - 1]
            for i, existing in enumerate(target.externals):
                if existing.path == ref.path:
                    return i + 1
            target.externals.append(copy.copy(ref))
            return len(target.externals)

        def remap(value):
            if isinstance(value, dict):
                if set(value) == {'m_FileID', 'm_PathID'}:
                    f, p = value['m_FileID'], value['m_PathID']
                    if not p:
                        return {'m_FileID': 0, 'm_PathID': 0}
                    return {'m_FileID': external(f), 'm_PathID': p if f else ids[p]}
                return {k: remap(v) for k, v in value.items()}
            if isinstance(value, list):
                return [remap(v) for v in value]
            return value

        def clone(old_id, new_id):
            donor = original[('level3', old_id)]
            obj = copy.copy(donor)
            typ = copy.copy(donor.serialized_type)
            if typ.script_type_index >= 0:
                script = copy.copy(source.script_types[typ.script_type_index])
                script.local_serialized_file_index = external(script.local_serialized_file_index)
                try:
                    typ.script_type_index = target.script_types.index(script)
                except ValueError:
                    typ.script_type_index = len(target.script_types)
                    target.script_types.append(script)
            typ.type_dependencies = ()
            target.types.append(typ)
            obj.assets_file, obj.path_id = target, new_id
            obj.type_id, obj.serialized_type = len(target.types) - 1, typ
            obj.data = donor.get_raw_data()
            obj._read_until = None
            target.objects[new_id] = obj
            return obj

        def pptr(path):
            return {'m_FileID': 0, 'm_PathID': path}

        for old, new in ids.items():
            obj = clone(old, new)
            if obj.type.name == 'MonoBehaviour':
                raw = bytearray(original[('level3', old)].get_raw_data())
                struct.pack_into('<iq', raw, 0, 0, ids[struct.unpack_from('<q', raw, 4)[0]])
                struct.pack_into('<i', raw, 16, external(struct.unpack_from('<i', raw, 16)[0]))
                if old == 650:
                    assert struct.unpack_from('<iq', raw, 88) == (3, 118)
                    struct.pack_into('<i', raw, 88, external(3))
                elif old == 619:
                    for offset, expected in ((104, 10865), (116, 1)):
                        assert struct.unpack_from('<iq', raw, offset) == (2, expected)
                        struct.pack_into('<i', raw, offset, external(2))
                    assert raw[88:100] == b'\x05\0\0\0v 1.0\0\0\0'
                    message = 'Завантаження…'.encode('utf8')
                    text = struct.pack('<I', len(message)) + message
                    text += bytes((-len(text)) % 4)
                    raw = raw[:88] + text + raw[100:]
                obj.set_raw_data(bytes(raw))
                continue
            tree = copy.deepcopy(original[('level3', old)].read_typetree())
            if old == 52:
                tree['m_Name'] = 'NXLoadingScreen'
                tree['m_Component'] = [{'component': pptr(ids[i])} for i in (449, 396, 706)]
            elif old == 6:
                tree['m_Name'] = 'NXLoadingBackground'
                tree['m_Component'] = [{'component': pptr(ids[i])} for i in (403, 221, 650)]
            elif old == 46:
                tree['m_Name'] = 'NXLoadingStatus'
            elif old == 449:
                tree['m_Children'] = [pptr(i) for i in (10006, 10010, 10014)]
                tree['m_LocalScale'] = {'x': 1.0, 'y': 1.0, 'z': 1.0}
            elif old == 396:
                tree['m_SortingOrder'] = -100
                tree['m_ReceivesEvents'] = False
            elif old == 403:
                tree['m_LocalScale'] = {'x': 1.8, 'y': 1.8, 'z': 1.0}
            elif old == 443:
                tree['m_AnchorMin'] = tree['m_AnchorMax'] = {'x': 0.5, 'y': 0.5}
                tree['m_Pivot'] = {'x': 0.5, 'y': 0.5}
                tree['m_AnchoredPosition'] = {'x': 0.0, 'y': -140.0}
                tree['m_SizeDelta'] = {'x': 500.0, 'y': 100.0}
            # New references are already local; remap donor references only.
            if old in (52, 6):
                obj.save_typetree(tree)
            elif old == 449:
                children = tree.pop('m_Children')
                tree = remap(tree)
                tree['m_Children'] = children
                obj.save_typetree(tree)
            else:
                obj.save_typetree(remap(tree))

        # Publisher logo used by the original splash, without a new texture.
        for old, new in ((6, 10013), (403, 10014), (221, 10015), (650, 10016)):
            obj = clone(old, new)
            if old == 6:
                tree = original[('level3', old)].read_typetree()
                tree['m_Name'] = 'NXLoadingLogo'
                tree['m_Component'] = [{'component': pptr(i)} for i in (10014, 10015, 10016)]
                obj.save_typetree(tree)
            elif old == 403:
                tree = remap(original[('level3', old)].read_typetree())
                tree['m_GameObject'] = pptr(10013)
                tree['m_LocalScale'] = {'x': 1.0, 'y': 1.0, 'z': 1.0}
                tree['m_AnchoredPosition'] = {'x': 0.0, 'y': 100.0}
                tree['m_SizeDelta'] = {'x': 900.0, 'y': 275.9765625}
                obj.save_typetree(tree)
            elif old == 221:
                obj.save_typetree({'m_GameObject': pptr(10013), 'm_CullTransparentMesh': False})
            else:
                raw = bytearray(original[('level3', old)].get_raw_data())
                struct.pack_into('<iq', raw, 0, 0, 10013)
                struct.pack_into('<i', raw, 16, external(1))
                struct.pack_into('<iq', raw, 88, external(1), 1258)
                obj.set_raw_data(bytes(raw))
        for ident in range(10001, 10017):
            added[(scene, ident)] = target.objects[ident].data
        target.mark_changed()
    return added


def verify_loading_screens(objects):
    from UnityPy.classes import PPtr
    for scene in ('level0', 'level1'):
        for ident in (10001, 10005, 10009, 10013):
            go = objects[(scene, ident)].read()
            assert go.m_IsActive
            for component in go.m_Component:
                assert component.component.deref().read(check_read=False).m_GameObject.m_PathID == ident
        canvas = objects[(scene, 10003)].read()
        assert canvas.m_SortingOrder == -100 and not canvas.m_ReceivesEvents
        for ident, expected in ((10008, 'bg'), (10016, 'appscraft_new')):
            obj = objects[(scene, ident)]
            file_id, path_id = struct.unpack_from('<iq', obj.get_raw_data(), 88)
            assert PPtr(m_FileID=file_id, m_PathID=path_id, assetsfile=obj.assets_file).read().m_Name == expected
        obj = objects[(scene, 10012)]
        raw = obj.get_raw_data()
        length = struct.unpack_from('<I', raw, 88)[0]
        assert raw[92:92+length].decode('utf8') == 'Завантаження…'
        font_offset = 96 + ((length + 3) // 4) * 4
        for offset, expected in ((font_offset, 'Goose SDF'), (font_offset + 12, 'Goose SDF Outline')):
            file_id, path_id = struct.unpack_from('<iq', raw, offset)
            ref = PPtr(m_FileID=file_id, m_PathID=path_id, assetsfile=obj.assets_file)
            assert ref.deref().read(check_read=False).m_Name == expected
        for ident in range(10001, 10017):
            obj = objects[(scene, ident)]
            if obj.type.name == 'MonoBehaviour':
                assert obj.read(check_read=False).m_Script.read().m_ClassName in {'Image', 'CanvasScaler', 'TextMeshProUGUI'}
        print(f'{scene}: loading hierarchy, ownership, scripts, sprites, text/font/material verified')
