# Single Game level locks — 2026-10-02

Requested: allow selecting all local modes without grinding profile levels.
No user database writes or fabricated games/wins are needed.

Confirmed in target `libil2cpp.so`, Build-ID
`d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0`:

- Assembly-CSharp.dll `SinglePlayerSelect.Start`, token `0x0600052b`,
  RID 1323, RVA `0xd7a518`. Resolution uses metadata and CodeGenModule
  method-pointer relocations; reproduction: `scripts/verify_single_game_unlock.py`.
- Metadata `gameType` field order: id, sceneName, lockLevel, isLocked,
  gameName, gameImage, Stat1, Stat2, isSolitaire. Runtime `isLocked` is at +0x24.
- Three loops read required level and profile level, compare with signed `gt`,
  and store the resulting bool into the newly created gameType.isLocked.
  Destination lists are +0xa0 otherTypes, +0x90 gameTypes, +0x98 solitaireTypes.
- `GameSelectElement.initBlock` (RVA `0xd6b0d4`) reads isLocked at
  `0xd6b188`, branches at `0xd6b194`, and configures locked/unlocked UI.
  SinglePlayerSelect.redrawGameList calls initBlock at `0xd79990`.
  Statistics populated by redrawGameList remain unmodified.

Only three instructions change in the writable staging image, before
`so_finalize` and guest execution:

| RVA | Original | Replacement | List |
|---|---|---|---|
| 0xd7a7f4 | 0x1a9fd7fc: cset w28,gt | 0x2a1f03fc: mov w28,wzr | otherTypes |
| 0xd7a990 | 0x1a9fd7fb: cset w27,gt | 0x2a1f03fb: mov w27,wzr | gameTypes |
| 0xd7ab38 | 0x1a9fd7fb: cset w27,gt | 0x2a1f03fb: mov w27,wzr | solitaireTypes |

Both old and new instructions preserve NZCV flags, registers other than the
destination, stack layout, and calling convention. No calls are intercepted;
hidden MethodInfo arguments and null/error paths remain intact. Required-level
values and sorting remain original, while isLocked becomes false.

The existing target-integrity check runs before patching. Additionally, each
site has a five-instruction exact fingerprint including the following call and
isLocked store. All three contexts are checked before any mutation; mismatch
aborts loading. The RX image is verified after mapping/cache flush. No writes
to executable memory or SD libil2cpp.so are performed by this change.

Validation: metadata/ELF/disassembly script confirmed 3/3 sites; native tests
cover mismatches in all 15 context words, truncated image, no partial patches,
exact replacements, and post-map corruption. Pinned Switch build, native
target/loader tests and 12 Python loader tests passed.

Install root `durak_nx.nro` at `/switch/durak_nx/durak_nx.nro`. Keep current
libraries, assets, saves and databases. This NRO also works with the previous
cosmetic menu bundle. Expected log: three `[SINGLE UNLOCK]` entries and
`[SINGLE UNLOCK OK]`. Check a previously locked mode can be selected and started,
returning to the menu retains access, and a restart retains access without
artificially increasing games/wins/level.

Status: NEEDS_HARDWARE_TEST. Unlocking selection does not prove every previously
untested game scene works on Switch; those scenes retain their original code.
