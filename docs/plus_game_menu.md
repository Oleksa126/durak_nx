# Plus opens the existing game menu

Target: Durak 25.0, IL2CPP Build-ID d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0.

The previous main-loop Plus handler unconditionally broke out of nativeRender.
Remove it and queue a request from padGetButtonsDown, not the held state.
Consume that request in the existing managed Input.touchCount callback, on an
already registered scripting thread. Do not invoke Unity scene APIs from the
host HID polling loop. Clear the request before invoking managed code so a
callback querying Input cannot repeat the operation.

Evidence from the original data.unity3d, read with UnityPy 1.25.3:

| Scene | Active button paths | Serialized Button onClick game handler |
| --- | --- | --- |
| level4 | GUI Layer/Widescreen/Menu Button; GUI Layer/Ipad/Menu Button | GameManager.GotoMenu |
| level6, level10 | Same two paths | ShowWinWindow |
| level5 | Screen/GUILayer/MenuButton | KlondikeManager.ShowGameExitWindow |

GameManager.GotoMenu (Assembly-CSharp token 0x060000e1, RVA 0xd111b4)
calls Window.Open at 0xd112bc -> 0xd84ae4, rather than directly changing scenes.
Window.Open is a zero-argument method, confirmed by metadata and the
Assembly-CSharp codegen method-pointer relocation. These addresses are evidence
only: the new dispatch adds no instruction patches or hardcoded managed offsets.

Resolve the exported il2cpp APIs from this verified target ELF. At request time,
resolve GameObject.Find(string), GetComponent(Type), and UnityEngine.UI.Button's
zero-argument Press via reflection. Press preserves the original active/
interactable checks and onClick listeners. GameObject.Find excludes inactive
objects. Main-menu and puzzle buttons are outside this path allowlist.
Managed exceptions are formatted and logged, then stop dispatch for that press.
No main-menu jump, synthetic screen coordinates, database edit, or new assets.

Native harness checks inactive scenes, one press per request, recursive Input
queries, and managed exceptions. Build/static checks cannot establish that the
expected gameplay window appears on the console.

Hardware gate: press Plus during a Durak match, confirm the existing game menu
opens and can be closed to resume; repeat Plus and check main-menu behavior.
Logs `[INPUT MENU] Plus -> Button.Press: ...` establish dispatch, not visible UI.
