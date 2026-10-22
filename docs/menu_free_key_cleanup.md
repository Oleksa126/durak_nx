# Free key prompt, crown and top-left label

Target Durak 25.0 libil2cpp Build-ID d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0.
Metadata Assembly-CSharp.WindowsInvoker.InvokeFreeKeyWnd token 0x060005ea,
zero explicit arguments and void return. CodegenModule relocation table resolves
the method to RVA 0xd8e9a0. Original five words:
`d100c3ff a90157fe a9024ff4 90008273 d0007274`.
Only the first instruction (stack allocation) becomes `ret` (d65f03c0), returning
before modifying SP. All five words must match before mutation; RX is verified
after mapping and cache flush. Native tests cover null, truncated image, every
fingerprint mismatch, unchanged neighbors and RX corruption.
`scripts/verify_single_game_unlock.py` verifies metadata, ABI, RVA and fingerprint.

Asset targets in level3:

- MainMenu/PremiumOfferButton: Image #680 (sprite `premium 1`, visually verified
  as gold crown), ButtonAdvanced #679, alert child Image #802.
- MainMenu/VersionString: TextMeshProUGUI #619, referenced by MainMenuController
  #707. Its RectTransform #443 anchors top-left, offset (20,-10), size
  (1202.117,70). Hide the display component while retaining the controller target.

Only m_Enabled bytes change. Objects, scripts, listeners and references remain.
The loading canvases clone the original enabled text payload, so their loading
message remains visible. All previous menu/loading changes are preserved.

New bundle: `.single-game-menu-final/assets/bin/Data/data.unity3d`.
Repack verified 25 original changes, 32 added presentation objects and 22556
unchanged original objects; nonserialized resource members match exactly.
SHA256: 903281f5d2915a622998e93c954e3eb4dd2ce7cd3c114a8a5330587806cbe153.

Deploy NRO to `/switch/durak_nx/durak_nx.nro` and bundle to
`/switch/durak_nx/game/assets/bin/Data/data.unity3d` on SD.
Hardware gate: no free key prompt, crown or top-left label; loading text, menu
buttons, Single Game and audio still work. No hardware success claimed yet.
