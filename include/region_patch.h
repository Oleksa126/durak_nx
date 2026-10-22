/* region_patch.h -- Durak libunity.so 256MB->64MB memory-region granularity
 * patch table (Unity 6000.0.58f2, arm64-v8a, ru.appscraft.durak v25.0).
 *
 * Target: libunity.so Build-ID bcc661ea2046416d
 * All 18 sites verified in extracted_durak/libunity.so.
 */
#ifndef REGION_PATCH_H
#define REGION_PATCH_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
  uint32_t off;
  uint32_t from;
  uint32_t to;
  const char *desc;
} DurakRegionPatch;

static const DurakRegionPatch DURAK_REGION_PATCH[] = {
  {0xfa116c, 0x12be0009, 0x12bf8009, "LocalLowLevelAllocator::ReserveMemoryBlock (256MB-1 mask hi)"},
  {0xfa117c, 0x92648d35, 0x92669535, "LocalLowLevelAllocator::ReserveMemoryBlock (~low28 mask)"},
  {0xfa19f8, 0x52a20008, 0x52a08008, "TLSAllocator::ThreadInitialize (256MB const)"},
  {0xfa406c, 0x52a20009, 0x52a08009, "BucketAllocator::ctor (256MB const)"},
  {0xfa60d8, 0x52a20009, 0x52a08009, "DynamicHeapAllocator::ctor (256MB region size)"},
  {0xfa65a4, 0x12be000d, 0x12bf800d, "DynamicHeapAllocator::RequestLargeAllocMemory (256MB-1 mask hi)"},
  {0xfa65d0, 0x92648d36, 0x92669536, "DynamicHeapAllocator::RequestLargeAllocMemory (~low28 mask)"},
  {0xfa7d90, 0xd35cdc33, 0xd35ad433, "VirtualAllocator::MarkMemoryBlocks (ubfx #28,#28)"},
  {0xfa7d98, 0xd35cfd15, 0xd35afd15, "VirtualAllocator::MarkMemoryBlocks (lsr #28)"},
  {0xfa7e3c, 0x52a20008, 0x52a08008, "VirtualAllocator::ReserveMemoryBlock (256MB const)"},
  {0xfa806c, 0xd35cfc28, 0xd35afc28, "VirtualAllocator::GetMemoryBlockFromPointer (lsr #28)"},
  {0xfa807c, 0x92646c28, 0x92667428, "VirtualAllocator::GetMemoryBlockFromPointer (~low28 mask)"},
  {0xfa8084, 0xd35c9c2a, 0xd35a942a, "VirtualAllocator::GetMemoryBlockFromPointer (ubfx #28,#12)"},
  {0xfa8098, 0xd35cdc29, 0xd35ad429, "VirtualAllocator::GetMemoryBlockFromPointer (ubfx #28,#28)"},
  {0xfa809c, 0xb25c6feb, 0xb25e77eb, "VirtualAllocator::GetMemoryBlockFromPointer (-255*gran hi)"},
  {0xfa80a0, 0xf2a2000b, 0xf2a0800b, "VirtualAllocator::GetMemoryBlockFromPointer (movk 256MB)"},
  {0xfa80e4, 0xcb0a7108, 0xcb0a6908, "VirtualAllocator::GetMemoryBlockFromPointer (sub lsl #28)"},
  {0xfa8108, 0xd35c9c29, 0xd35a9429, "VirtualAllocator::GetBlockInfoFromPointer (ubfx #28,#12)"},
};
#define DURAK_REGION_PATCH_N ((int)(sizeof(DURAK_REGION_PATCH)/sizeof(DURAK_REGION_PATCH[0])))

int durak_patch_unity_regions(void *staging_load_base, size_t load_size);
int durak_verify_unity_regions_post_map(const void *virtbase, size_t load_size);

/* ChoreographerBase::Get fallback patch (Frame 142/143 hang fix)
 * Target: libunity.so RVA 0x00e7261c
 * Replaces ChoreographerBase::Get() entry with { mov x0, #0; ret; }
 * Both callers (0x00e7258c and 0x00e72770) have verified 'cbz x0' fallbacks.
 */
static const DurakRegionPatch DURAK_CHOREOGRAPHER_PATCH[] = {
  {0x00e7261c, 0xd10143ff, 0xd2800000, "ChoreographerBase::Get (movz x0, #0)"},
  {0x00e72620, 0xa90357fe, 0xd65f03c0, "ChoreographerBase::Get (ret)"},
};
#define DURAK_CHOREOGRAPHER_PATCH_N ((int)(sizeof(DURAK_CHOREOGRAPHER_PATCH)/sizeof(DURAK_CHOREOGRAPHER_PATCH[0])))

int durak_patch_unity_choreographer(void *staging_load_base, size_t load_size);
int durak_verify_unity_choreographer_post_map(const void *virtbase, size_t load_size);

/* Assembly-CSharp metadata token 0x0600052b: SinglePlayerSelect.Start.
 * Durak 25.0 libil2cpp Build-ID d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0.
 * Five-word context: mov x0,x25; cset w27/28,gt; ldr x2; bl; strb isLocked.
 * Only cset changes to mov w27/28,wzr. No profile/statistics writes.
 */
typedef struct {
  uint32_t off;
  uint32_t context[5];
  uint32_t unlocked;
} DurakSingleGameUnlock;
/* Target libunity bcc661ea2046416d: AudioTrack=23, OpenSL ES=24.
 * Change only the AudioTrack selections, preserving NOSOUND and other branches. */
static const DurakSingleGameUnlock DURAK_AUDIO_OUTPUT_PATCH[] = {
  {0x85e0a4, {0x528002e8, 0xb9000268, 0x14000005, 0x52800328, 0x52800029}, 0x52800308},
  {0x108d874, {0x528002e8, 0xb9000268, 0x14000007, 0x528004a0, 0xd65f03c0}, 0x52800308},
};
int durak_patch_audio_output(void *base, size_t size);
int durak_verify_audio_output(const void *base, size_t size);
static const DurakSingleGameUnlock DURAK_SINGLE_GAME_UNLOCK[] = {
  {0xd7a7f0, {0xaa1903e0, 0x1a9fd7fc, 0xf9400102, 0x94020ab7, 0x3900931c}, 0x2a1f03fc},
  {0xd7a98c, {0xaa1903e0, 0x1a9fd7fb, 0xf9400102, 0x94020a50, 0x3900931b}, 0x2a1f03fb},
  {0xd7ab34, {0xaa1903e0, 0x1a9fd7fb, 0xf9400102, 0x940209e6, 0x3900931b}, 0x2a1f03fb},
};
#define DURAK_SINGLE_GAME_UNLOCK_N 3
int durak_patch_single_game_unlock(void *staging, size_t size);
int durak_verify_single_game_unlock(const void *mapped, size_t size);

/* Assembly-CSharp.WindowsInvoker.InvokeRateWnd (void instance method).
 * Suppress only the automatic rating prompt; preserve other window invocations.
 */
#define DURAK_RATE_PROMPT_RVA 0xd8e8ac
static const uint32_t DURAK_RATE_PROMPT_CONTEXT[] = {
  0xf81d0ffe, 0xa90157f6, 0xa9024ff4, 0x90008274, 0xb0007296
};
int durak_patch_rate_prompt(void *staging, size_t size);
int durak_verify_rate_prompt(const void *mapped, size_t size);

/* WindowsInvoker.InvokeFreeKeyWnd, token 0x060005ea; void, zero parameters.
 * Resolve through target Assembly-CSharp codegen module, not a donor RVA. */
#define DURAK_FREE_KEY_PROMPT_RVA 0xd8e9a0
/* DRAFT.ShowPremimBannerWnd: skip only index 1 (PremiumOfferWnd).
 * The checked allocation creates exactly 3 entries; replace its redundant
 * length==1 guard with index==1 -> the existing balanced epilogue. */
#define DURAK_PREMIUM_OFFER_RVA 0xcf6120
static const uint32_t DURAK_PREMIUM_OFFER_CONTEXT[] = {
  0xf94002a0, 0x52800061, 0x97fbb752, 0xb40008e0,
  0xb9401808, 0x34000888, 0x90007729, 0x7100051f,
  0xf9441929, 0xf9400129, 0xf9001009, 0x540007c0
};
int durak_patch_premium_offer(void *staging, size_t size);
int durak_verify_premium_offer(const void *mapped, size_t size);
/* SinglePlayerSelect.OnEnable token 0x0600052c, RVA 0xd7ae44.
 * Skip only direct Windows/PremiumWindows/PremiumOfferWnd instantiation;
 * continue at the original non-offer path that selects the active game tab. */
#define DURAK_SINGLE_PREMIUM_RVA 0xd7b0b0
static const uint32_t DURAK_SINGLE_PREMIUM_CONTEXT[] = {
  0xf9403508, 0xb40008e8, 0xb9411108, 0x6b00011f,
  0x5400054a, 0xf0007308, 0x90007309, 0xf9460508,
  0xf9416529, 0xf9400100, 0xf9400121, 0x9402370a
};
static const uint32_t DURAK_FREE_KEY_PROMPT_CONTEXT[] = {
  0xd100c3ff, 0xa90157fe, 0xa9024ff4, 0x90008273, 0xd0007274
};
int durak_patch_free_key_prompt(void *staging, size_t size);
int durak_verify_free_key_prompt(const void *mapped, size_t size);

/* GadgetSelectWindow.useGadget token 0x06000416. Quantity is at +0x1c,
 * verified against MetricsTypes.gadgets.get_number. Keep the quantity and
 * flags, then execute the original update, effect and action-record paths. */
#define DURAK_GADGET_STOCK_RVA 0xd67690
static const uint32_t DURAK_GADGET_STOCK_CONTEXT[] = {
  0xb940182a, 0xb9412529, 0x6b09015f, 0x54fffac1,
  0xb9401c29, 0x71000529, 0x54fffa6b, 0xb9001c29,
  0xf9401d00, 0xb40008e0, 0xf9400342, 0x9401bee8
};
int durak_patch_gadget_stock(void *base, size_t size);
int durak_verify_gadget_stock(const void *base, size_t size);

#endif /* REGION_PATCH_H */
