# PremiumOfferWnd suppression

Target Durak 25.0 / libil2cpp Build-ID d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0.
User requested the automatic “2 times more keys / buy premium” modal removed.

Original resources.assets GameObject 4444 is PremiumOfferWnd. Its children
include Title2/Localizator (`want_to_get`), PremiumBenefits/KeysBenefit, and
BuyButton. Do not hide its images while leaving an invisible modal active.

DRAFT.ShowPremimBannerWnd(index), metadata token 0x0600000a, resolves via
Assembly-CSharp codegen relocation to 0xcf607c. Original `mov w19,w1` retains
the instance method's integer argument. It allocates a three-entry string array
and stores the literal PremiumOfferWnd into element 1 (offset 0x28).
Relocation 0x1bdb310 points at the encoded string usage for literal 6306.

Replace the redundant length==1 guard after the allocation with index==1:
`cmp w8,#1` -> `cmp w19,#1` at 0xcf613c, and change the following b.eq at
0xcf614c to the existing balanced return epilogue 0xcf6234. The allocation is
still exactly 3; other indices proceed through their existing range checks.
Index 1 returns before looking up, instantiating, or opening the window.
No purchases, premium state, rewards, or databases are changed.

## Direct Single Game path (2026-10-02)

User hardware feedback reports the modal still appears. The earlier patch
covered only DRAFT; SinglePlayerSelect.OnEnable (token 0x0600052c, RVA 0xd7ae44)
loads Windows/PremiumWindows/PremiumOfferWnd directly. Relocation 0x1bdec08
resolves encoded metadata string literal 8996. The block at 0xd7b0c4 loads
this resource, instantiates it and calls Window.Open at 0xd7b164.

Change the original b.ge at 0xd7b0c0 to an unconditional branch with the same
target 0xd7b168. This bypasses only creation/opening of that offer and retains
the existing continuation, including showTab at 0xd7b1b8 and balanced epilogue.
Both DRAFT and Single Game fingerprints are checked before any write and after
RX mapping. Native tests corrupt every context word and check atomic rejection;
the package gate now runs the metadata/literal/instruction verifier.

Status: NEEDS_HARDWARE_TEST. Enter Single Game repeatedly and after a match;
the offer must be absent and the mode tabs must remain selectable.

Check all 12 original words including allocation length before either write;
verify both replacements and remaining words after RX mapping. ELF identity
verification already covers the full original module. Reproducible proof:
`python scripts/verify_single_game_unlock.py` with capstone/pyelftools available.
Native harness rejects all mismatched fingerprint words without mutation.
Visible absence still needs a Switch test after the original trigger.

The supplied PNG is converted to RGB JPEG 256×256 in root icon.jpg, which the
existing Makefile embeds in the NRO for Homebrew Menu. No Unity asset replacement
is needed for either change.
