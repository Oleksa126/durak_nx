# Loading presentation, Our Games and rating prompt — 2026-10-02

User authorized replacing the empty startup interval with a loading screen,
hiding Our Games and suppressing Rate the Game.

## Asset changes

`scripts/hide_main_menu_extras.py` now uses `loading_screen_assets.py` to add
16 presentation-only objects to each of level0 (DatabaseImporter) and level1
(globals/database initialization). IDs 10001–10016 are checked unused first.
The two canvases contain the existing wood background, original splash logo
`appscraft_new`, and `Завантаження…` text using the existing Goose SDF font.
Original sprite/font resources are referenced; no texture edits or new shaders.

CanvasScaler is cloned from the menu. Root scale is 1, Canvas sorting order -100,
no GraphicRaycaster or game controller is added. The opaque main-menu UI at
sorting order 0 covers loading presentation once shown. The canvases are normal
scene objects, not DontDestroyOnLoad objects. Normal scene unloading removes
them. Existing DatabaseImporter/SceneLoader lifecycle and SQLite initialization
remain unmodified. A synchronous engine/DB call can still block rendering; this
change provides presentation when the bootstrap scenes render, and does not
claim to make those calls asynchronous or guarantee a continuously animating UI.
No percentage is displayed, since the database phase has no measured progress.

Our Games hierarchy `MainMenu/OurGamesScaler` has Images 664, 678, 827 and
ButtonAdvanced 652 disabled. Other main-menu changes from previous requests
remain included.

Verification reloads the packed bundle, checks every original object payload,
all added payloads, untouched streamed resources, component ownership and
script/sprite/font/material references. Types/script table indices and external
file references are remapped into each destination scene. Result: 21 intentional
changes, 32 added objects, 22560 original objects unchanged.
SHA256: `71dfba5508059ca640344ba76a10ba72e75baf8008f01ac73ed9d38b5aa412b9`.

## Rating prompt

Metadata resolves Assembly-CSharp.WindowsInvoker.InvokeRateWnd, token
`0x060005e9`, void instance method with no explicit parameters, RVA `0xd8e8ac`.
Its body creates/schedules a rating callback through MegaBehavior.Perform and
StartCoroutine. The automatic scene-change path calls this method; the nearby
InvokeFreeKeyWnd method is separate and unchanged.

Replace only the first instruction `0xf81d0ffe` (str x30,[sp,#-0x30]!) with
`0xd65f03c0` (ret). This returns before stack modification, leaving caller
registers/SP and hidden MethodInfo intact. Five original instruction words must
match before mutation; target integrity is checked by the existing loader.
Patch occurs in writable staging, followed by RX verification after mapping.
SD libil2cpp.so and user rating/profile state are not edited.

`verify_single_game_unlock.py` resolves metadata and checks the original
fingerprint. Native tests cover null/truncated images, mismatches in every
context word without partial writes, replacement, preservation of neighboring
instructions, and post-map corruption. Pinned Switch build, native tests and
12 Python loader checks passed.

## Hardware gate

Install root durak_nx.nro at `/switch/durak_nx/durak_nx.nro`, and generated
`.single-game-loading-final/assets/bin/Data/data.unity3d` at
`/switch/durak_nx/game/assets/bin/Data/data.unity3d`, preserving the original
bundle as backup. These replace the previous startup files and retain unlock.

NEEDS_HARDWARE_TEST: confirm text/font/position/background, transition to an
interactive menu, disappearance of Our Games and automatic rating popup, and
Single Game after loading. If a blank interval remains before either bootstrap
scene renders, localize it using the startup log before adding another renderer
or altering initialization order.
