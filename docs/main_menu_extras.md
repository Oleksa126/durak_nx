# Main menu presentation — 2026-10-02

User requested hiding the publisher logo, the main-menu Info/VK/NoAds controls,
and the key/chest blocks including Open. Implementation changes assets only.

`scripts/hide_main_menu_extras.py` requires UnityPy 1.25.3. Run from root:

```powershell
python scripts/hide_main_menu_extras.py extracted_durak/sdmc/switch/durak_nx/assets/bin/Data/data.unity3d .single-game-menu/assets/bin/Data/data.unity3d
```

The script refuses an existing output or overwriting the input. It disables
the serialized `m_Enabled` flag of 15 Image/TextMeshProUGUI/ButtonAdvanced
components below exact level3 paths MainMenu/Info, MainMenu/VK,
MainMenu/NoAdsButton, MainMenu/KeyBlock, MainMenu/ChestBlock. Expected component
IDs and hierarchy are checked before saving. Objects, controllers, animation
references, localization, and SinglePlayer/SinglePlayerNarrow Info buttons remain.

The publisher logo is baked into the `bg` sprite, not a label. Only MainMenu/Background
RectTransform #403 changes uniform XY scale from 1.3299 to 1.8. This zooms the
wooden background and crops its branding below the screen. No texture editing,
new scene objects, IL2CPP/ARM64 patches, database changes, or NRO changes.
CanvasScaler #706 has reference resolution 2048x1536 and matches height.
The enlarged background height is 1151*1.8=2071.8 reference units; the branding
near the lower edge lies below the visible -768 boundary. Hardware appearance
and returning to the menu still require validation.

Repacked output was reloaded successfully. All 22581 serialized objects were
compared: 16 intentional changes, 22565 identical raw payloads; all other bundle
members, including streamed resources, are byte-identical. Output size 32272383.
SHA256: `d9fe218d98f010a33720fe0bcca8dfa590f0c6d3e51798ef10aa8e9f14c57d44`.

Log 19 lines 1593–1600 prove this console opens
`sdmc:/switch/durak_nx/game/assets/bin/Data/data.unity3d`. Keep the original
bundle outside this active path as a backup and replace only that bundle with
the generated file. Keep the working NRO. Check all requested elements are
hidden, their old positions do not accept clicks, Single Game still shows modes
and starts a game, and returning to the main menu preserves the hiding.

Status: NEEDS_HARDWARE_TEST. Serialized-data checks cannot prove that runtime
scripts or animations never re-enable these components.

Startup cleanup revision: the current script also makes the level0 bootstrap
camera black. The earlier 16-object count/hash above describes commit 67a08ab;
the current combined bundle has 17 changes, documented in startup_cleanup.md.
