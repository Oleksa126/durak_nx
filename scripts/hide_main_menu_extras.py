"""Patch Durak 25.0 menu presentation; requires UnityPy==1.25.3.

Writes a separate bundle, preserving game objects and controller references.
Every serialized object is compared after repacking; only listed bytes may change.
"""
import argparse
import hashlib
import struct
from pathlib import Path

import UnityPy

ROOTS = {'MainMenu/Info', 'MainMenu/VK', 'MainMenu/NoAdsButton',
         'MainMenu/KeyBlock', 'MainMenu/ChestBlock', 'MainMenu/OurGamesScaler',
         'MainMenu/PremiumOfferButton', 'MainMenu/VersionString'}
UI_CLASSES = {'Image', 'TextMeshProUGUI', 'ButtonAdvanced'}
UI_IDS = {649, 662, 611, 717, 757, 758, 776, 777, 804, 835, 834,
          898, 899, 900, 646, 652, 664, 678, 827, 680, 679, 802, 619}
COSMETIC_HINTS = (
    ('SelectAvatar/Content/Image', 'get_new_avatar', 13150, 11376, 13557),
    ('SelectCover/Content/Image', 'get_new_cover', 12844, 11209, 14454),
    ('SelectGadget/Content/Image', 'get_new_gadget', 13130, 11349, 13573),
)
COSMETIC_HINT_BACKGROUNDS = (
    ('SelectAvatar/Content/InfoBack', 13275, 1091, 'info-bg'),
    ('SelectCover/Content/InfoBack', 12664, 1091, 'info-bg'),
    ('SelectGadget/Content/InfoBack', 14385, 1091, 'info-bg'),
    ('SelectAvatar/Content/BottomGr', 12194, 1254, 'bottom-gr'),
    ('SelectCover/Content/BottomGr', 10920, 1254, 'bottom-gr'),
)


def hierarchy(go):
    names = [go.m_Name]
    transform = next(c.component.read() for c in go.m_Component
                     if c.component.type.name in {'Transform', 'RectTransform'})
    while transform.m_Father.m_PathID:
        transform = transform.m_Father.read()
        names.append(transform.m_GameObject.read().m_Name)
    return '/'.join(reversed(names))


def objects(env):
    return {(o.assets_file.name, o.path_id): o for o in env.objects}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve() or args.output.exists():
        parser.error('Output must be a new file, separate from the original bundle')
    env = UnityPy.load(str(args.input))
    original = objects(env)
    before = {k: hashlib.sha256(o.get_raw_data()).digest()
              for k, o in original.items()}
    changes = {}
    found = set()
    for key, obj in original.items():
        if obj.assets_file.name != 'level3' or obj.type.name != 'GameObject':
            continue
        go = obj.read()
        path = hierarchy(go)
        if path in ROOTS:
            found.add(path)
        if not any(path == root or path.startswith(root + '/') for root in ROOTS):
            continue
        for component in go.m_Component:
            reader = component.component.deref()
            if reader.type.name != 'MonoBehaviour':
                continue
            behaviour = reader.read(check_read=False)
            name = behaviour.m_Script.read().m_ClassName
            if name not in UI_CLASSES:
                continue
            raw = reader.get_raw_data()
            # Unity's serialized MonoBehaviour base: GO PPtr(12), enabled(1).
            if struct.unpack_from('<iq', raw) != (0, obj.path_id) or raw[12] != 1:
                raise ValueError(f'Unexpected enabled behaviour layout: {path}/{name}')
            updated = raw[:12] + b'\0' + raw[13:]
            reader.set_raw_data(updated)
            changes[(reader.assets_file.name, reader.path_id)] = updated
            print(f'Hide {path}: {name} #{reader.path_id}')
    if found != ROOTS or {key[1] for key in changes} != UI_IDS:
        raise ValueError(f'Unexpected menu version: roots={found}, components={len(changes)}')

    # Original localized chest/key acquisition hints are obsolete after the
    # local inventory unlock. Hide their panel and text, retaining controllers,
    # localization bindings and all item selection references.
    for path, localization_key, localization_id, image_id, text_id in COSMETIC_HINTS:
        localization = original[('resources.assets', localization_id)]
        behaviour = localization.read(check_read=False)
        if (behaviour.m_Script.read().m_ClassName != 'SimpleLocalization'
                or hierarchy(behaviour.m_GameObject.read()) != path + '/ChooseAvatarInfo'
                or localization.get_raw_data().count(localization_key.encode()) != 1):
            raise ValueError(f'Unexpected cosmetic hint localization: {path}')
        for component_id, class_name, expected_path in (
                (image_id, 'Image', path),
                (text_id, 'TextMeshProUGUI', path + '/ChooseAvatarInfo')):
            reader = original[('resources.assets', component_id)]
            behaviour = reader.read(check_read=False)
            raw = reader.get_raw_data()
            if (behaviour.m_Script.read().m_ClassName != class_name
                    or hierarchy(behaviour.m_GameObject.read()) != expected_path
                    or struct.unpack_from('<iq', raw) != (0, behaviour.m_GameObject.m_PathID)
                    or raw[12] != 1):
                raise ValueError(f'Unexpected cosmetic hint component: {expected_path}')
            updated = raw[:12] + b'\0' + raw[13:]
            reader.set_raw_data(updated)
            changes[('resources.assets', component_id)] = updated
            print(f'Hide {expected_path}: {class_name} #{component_id}')

    # The hint's info icon is a sibling of its full-width info-bg and bottom-gr
    # decorations. Suppress those separate renderers as well.
    for path, component_id, sprite_id, sprite_name in COSMETIC_HINT_BACKGROUNDS:
        reader = original[('resources.assets', component_id)]
        behaviour = reader.read(check_read=False)
        raw = reader.get_raw_data()
        sprite = original[('resources.assets', sprite_id)]
        go = behaviour.m_GameObject.read()
        transform = next(c.component.deref() for c in go.m_Component
                         if c.component.type.name == 'RectTransform').read_typetree()
        if (behaviour.m_Script.read().m_ClassName != 'Image'
                or hierarchy(go) != path
                or struct.unpack_from('<iq', raw) != (0, go.object_reader.path_id)
                or len(raw) != 136 or raw[12] != 1
                or struct.unpack_from('<iq', raw, 88) != (0, sprite_id)
                or sprite.type.name != 'Sprite' or sprite.read().m_Name != sprite_name
                or not -450 <= transform['m_AnchoredPosition']['y'] <= -430
                or transform['m_SizeDelta']['x'] < 1200):
            raise ValueError(f'Unexpected cosmetic hint background: {path}')
        updated = raw[:12] + b'\0' + raw[13:]
        reader.set_raw_data(updated)
        changes[('resources.assets', component_id)] = updated
        print(f'Hide {path}: Image #{component_id} sprite={sprite_name}')

    # APPSCRAFT is baked into sprite "bg", near its bottom edge. Uniformly
    # enlarge only the MainMenu background to crop that edge off the viewport.
    # Preserve texture, sprite, other scenes, and aspect ratio.
    bg = original[('level3', 403)]
    tree = bg.read_typetree()
    if hierarchy(bg.read().m_GameObject.read()) != 'MainMenu/Background':
        raise ValueError('Unexpected background object')
    if tree['m_SizeDelta'] != {'x': 2048.0, 'y': 1151.0}:
        raise ValueError('Unexpected background dimensions')
    raw = bg.get_raw_data()
    expected = struct.pack('<fff', 1.3299000263214111, 1.3299000263214111, 1.3299000263214111)
    if raw.count(expected) != 1:
        raise ValueError('Unexpected background scale layout')
    updated = raw.replace(expected, struct.pack('<fff', 1.8, 1.8, 1.3299000263214111))
    bg.set_raw_data(updated)
    changes[('level3', 403)] = updated

    # level0 is the DatabaseImporter bootstrap scene (hardware log 19).
    # Its camera clears to Unity's default blue while databases initialize.
    camera = original[('level0', 5)]
    tree = camera.read_typetree()
    if camera.type.name != 'Camera' or camera.read().m_GameObject.read().m_Name != 'Main Camera':
        raise ValueError('Unexpected bootstrap camera')
    expected_color = struct.pack('<ffff', 0.1921568661928177,
                                 0.3019607961177826, 0.4745098054409027, 0.0)
    raw = camera.get_raw_data()
    if tree['m_ClearFlags'] != 1 or raw.count(expected_color) != 1:
        raise ValueError('Unexpected bootstrap camera background')
    updated = raw.replace(expected_color, struct.pack('<ffff', 0.0, 0.0, 0.0, 0.0))
    camera.set_raw_data(updated)
    changes[('level0', 5)] = updated

    # The host already owns the continuous loading image. Disable the hidden
    # Unity splash timer, retaining all other PlayerSettings bytes (including
    # the four-byte Unity 6 tail absent from UnityPy's generated typetree).
    settings = original[('globalgamemanagers', 1)]
    raw = settings.get_raw_data()
    if hashlib.sha256(raw).hexdigest() != 'b9e31b1407f3994496b519faa4682a145a099bf7b4e7041f9ce2b937a0d607cf':
        raise ValueError('Unexpected PlayerSettings version')
    tree = settings.read_typetree(check_read=False)
    encoded = settings.save_typetree(tree)
    if len(encoded) != 880 or raw[:880] != encoded or raw[880:] != b'\x03\0\0\0':
        raise ValueError('Unexpected PlayerSettings roundtrip/tail')
    if tree['m_ShowUnitySplashScreen'] is not True:
        raise ValueError('Unexpected original splash setting')
    tree['m_ShowUnitySplashScreen'] = False
    updated_prefix = settings.save_typetree(tree)
    if [i for i, (a, b) in enumerate(zip(encoded, updated_prefix)) if a != b] != [100]:
        raise ValueError('Splash edit changed unrelated settings')
    updated = updated_prefix + raw[880:]
    settings.set_raw_data(updated)
    changes[('globalgamemanagers', 1)] = updated

    # SimpleSQL's existing overwriteIfExists flag deletes a valid localization
    # DB each startup. Preserve it; its native Initialize still copies the
    # bundled DB when missing. No metrics or dictionary manager flag changes.
    sql = original[('level1', 53)]
    raw = sql.get_raw_data()
    behaviour = sql.read(check_read=False)
    if (hashlib.sha256(raw).hexdigest() != '1c508eb309feda69aa3de3ad63f6bdb8e224aa5b09adc09ec6809fdd5a85d760'
            or behaviour.m_Script.read().m_ClassName != 'SimpleSQLManager'
            or behaviour.m_GameObject.read().m_Name != 'L10n'
            or struct.unpack_from('<iq', raw, 32) != (2, 7)
            or original[('sharedassets1.assets', 7)].read().m_Name != 'l10n'
            or raw[60:64] != b'\x01\0\0\0'):
        raise ValueError('Unexpected localization SQL manager layout')
    updated = raw[:60] + b'\0' + raw[61:]
    sql.set_raw_data(updated)
    changes[('level1', 53)] = updated
    print('Startup: hidden Unity splash disabled; existing l10n database retained')

    added = {}
    packed = env.file.save(packer='original')
    reloaded = UnityPy.load(packed)
    check = objects(reloaded)
    if env.file.files.keys() != reloaded.file.files.keys():
        raise ValueError('Repacking changed the bundle file inventory')
    for name, member in env.file.files.items():
        if not hasattr(member, 'objects'):
            if member.bytes != reloaded.file.files[name].bytes:
                raise ValueError(f'Unrelated bundle resource changed: {name}')
    if check.keys() != original.keys() | added.keys():
        raise ValueError('Repacking changed the object inventory')
    for key, reader in check.items():
        actual = reader.get_raw_data()
        if key in added:
            if actual != added[key]:
                raise ValueError(f'Loading object failed verification: {key}')
        elif key in changes:
            if actual != changes[key]:
                raise ValueError(f'Patch failed verification: {key}')
        elif hashlib.sha256(actual).digest() != before[key]:
            raise ValueError(f'Unrelated object changed: {key}')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(packed)
    print(f'Verified {len(changes)} changes, {len(added)} additions; {len(original)-len(changes)} unchanged.')
    print(f'Output: {args.output}; SHA256: {hashlib.sha256(packed).hexdigest()}')


if __name__ == '__main__':
    main()
