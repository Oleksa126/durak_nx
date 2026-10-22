# Single original loading screen

Historical: superseded by the user's request to cover the remaining black
intervals with a continuous shared loading image; see continuous_loading.md.

The user reported three sequential loading presentations: early host framebuffer,
original Unity splash, and NXLoadingScreen in DatabaseImporter/globals scenes.
Removed the host framebuffer code and embedded logo, along with its build/tests.
Asset builder no longer inserts the 32 extra loading objects. Original Unity
splash/player settings are untouched. This deliberately restores the original
loading presentation rather than maintaining three different screens.

Build the bundle from the original extracted data.unity3d so previous injected
objects cannot remain. Verify 25 intentional original object changes, zero added
objects, 22556 unchanged originals, and unchanged resource members. These 25
changes retain all requested menu hides/background crop and bootstrap black
clear color. NRO retains sound, memory correction, Single Game unlock, rate/free
key suppression and constructor sync optimization.

Output: `.single-game-one-loader/assets/bin/Data/data.unity3d`.
Deploy NRO -> `/switch/durak_nx/durak_nx.nro` and bundle ->
`/switch/durak_nx/game/assets/bin/Data/data.unity3d`.

Before Unity can render, black screen may remain. This change removes duplicate
presentation; it does not eliminate loading work or claim a seamless image from
title selection. Hardware gate: only original splash, then menu; audio and input
remain working. Earlier loading documentation is historical for superseded UI.
