/* region_patch.c -- Implementation of Durak libunity 256MB->64MB region patch
 * Fail-closed verification and application before so_finalize.
 */

#include "region_patch.h"
#include "util.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int check_gadget_stock(const void *base,size_t size,int patched) {
  if(!base || size<DURAK_GADGET_STOCK_RVA+sizeof(DURAK_GADGET_STOCK_CONTEXT)) return -1;
  for(int i=0;i<12;++i) {
    uint32_t actual,expected=DURAK_GADGET_STOCK_CONTEXT[i];
    if(patched && i==5) expected=0x71000129; /* subs w9,w9,#0 */
    memcpy(&actual,(const char *)base+DURAK_GADGET_STOCK_RVA+i*4,4);
    if(actual!=expected) {
      durak_log_printf("[INVENTORY ERROR] Gadget stock RVA=0x%x actual=0x%08x expected=0x%08x\n",
                       DURAK_GADGET_STOCK_RVA+i*4,actual,expected);
      return -2;
    }
  }
  return 0;
}
int durak_patch_gadget_stock(void *base,size_t size) {
  int rc=check_gadget_stock(base,size,0); if(rc) return rc;
  uint32_t instruction=0x71000129;
  memcpy((char *)base+DURAK_GADGET_STOCK_RVA+5*4,&instruction,4);
  durak_log_printf("[INVENTORY] Gadget consumption disabled; effect and database update retained\n");
  return 0;
}
int durak_verify_gadget_stock(const void *base,size_t size) {
  return check_gadget_stock(base,size,1);
}

static int check_audio_output(const void *base, size_t size, int patched) {
  if (!base) return -1;
  for (int i = 0; i < 2; ++i) {
    const DurakSingleGameUnlock *site = &DURAK_AUDIO_OUTPUT_PATCH[i];
    if (site->off > size || size - site->off < sizeof(site->context)) return -1;
    for (int j = 0; j < 5; ++j) {
      uint32_t word;
      memcpy(&word, (const char *)base + site->off + j * 4, 4);
      uint32_t expected = patched && j == 0 ? site->unlocked : site->context[j];
      if (word != expected) {
        durak_log_printf("[AUDIO ERROR] RVA 0x%x actual=0x%08x expected=0x%08x\n",
                         site->off + j * 4, word, expected);
        durak_log_flush();
        return -2;
      }
    }
  }
  return 0;
}
int durak_patch_audio_output(void *base, size_t size) {
  int rc = check_audio_output(base, size, 0);
  if (rc) return rc;
  for (int i = 0; i < 2; ++i)
    memcpy((char *)base + DURAK_AUDIO_OUTPUT_PATCH[i].off,
           &DURAK_AUDIO_OUTPUT_PATCH[i].unlocked, 4);
  durak_log_printf("[AUDIO] AudioTrack(23) selections redirected to OpenSL ES(24)\n");
  durak_log_flush();
  return 0;
}
int durak_verify_audio_output(const void *base, size_t size) {
  int rc = check_audio_output(base, size, 1);
  if (!rc) durak_log_printf("[AUDIO] OpenSL ES selections verified in RX image\n");
  durak_log_flush();
  return rc;
}

static int check_premium_offer(const void *base, size_t size, int patched) {
  if (!base || size < DURAK_PREMIUM_OFFER_RVA + sizeof(DURAK_PREMIUM_OFFER_CONTEXT)) return -1;
  if (size < DURAK_SINGLE_PREMIUM_RVA + sizeof(DURAK_SINGLE_PREMIUM_CONTEXT)) return -1;
  for (int i = 0; i < 12; ++i) {
    uint32_t word, expected = DURAK_SINGLE_PREMIUM_CONTEXT[i];
    if (patched && i == 4) expected = 0x1400002a; /* b 0xd7b168 */
    memcpy(&word, (const char *)base + DURAK_SINGLE_PREMIUM_RVA + i * 4, 4);
    if (word != expected) {
      durak_log_printf("[PREMIUM OFFER ERROR] Single Game RVA 0x%x actual=0x%08x expected=0x%08x\n",
                       DURAK_SINGLE_PREMIUM_RVA + i * 4, word, expected);
      durak_log_flush();
      return -2;
    }
  }
  for (int i = 0; i < 12; ++i) {
    uint32_t word, expected = DURAK_PREMIUM_OFFER_CONTEXT[i];
    if (patched && i == 7) expected = 0x7100067f; /* cmp w19, #1 */
    if (patched && i == 11) expected = 0x54000740; /* b.eq 0xcf6234 */
    memcpy(&word, (const char *)base + DURAK_PREMIUM_OFFER_RVA + i * 4, 4);
    if (word != expected) {
      durak_log_printf("[PREMIUM OFFER ERROR] RVA 0x%x actual=0x%08x expected=0x%08x\n",
                       DURAK_PREMIUM_OFFER_RVA + i * 4, word, expected);
      durak_log_flush();
      return -2;
    }
  }
  return 0;
}
int durak_patch_premium_offer(void *base, size_t size) {
  int rc = check_premium_offer(base, size, 0);
  if (rc) return rc;
  uint32_t compare = 0x7100067f, branch = 0x54000740;
  memcpy((char *)base + DURAK_PREMIUM_OFFER_RVA + 7 * 4, &compare, 4);
  memcpy((char *)base + DURAK_PREMIUM_OFFER_RVA + 11 * 4, &branch, 4);
  branch = 0x1400002a;
  memcpy((char *)base + DURAK_SINGLE_PREMIUM_RVA + 4 * 4, &branch, 4);
  durak_log_printf("[PREMIUM OFFER] DRAFT index 1 and Single Game direct offer bypassed\n");
  return 0;
}
int durak_verify_premium_offer(const void *base, size_t size) {
  return check_premium_offer(base, size, 1);
}

static int check_rate_prompt(const void *base, size_t size, int patched) {
  if (!base || size < DURAK_RATE_PROMPT_RVA + sizeof(DURAK_RATE_PROMPT_CONTEXT)) return -1;
  for (int i = 0; i < 5; ++i) {
    uint32_t word;
    memcpy(&word, (const char *)base + DURAK_RATE_PROMPT_RVA + i * 4, 4);
    uint32_t expected = patched && i == 0 ? 0xd65f03c0 : DURAK_RATE_PROMPT_CONTEXT[i];
    if (word != expected) {
      durak_log_printf("[RATE PROMPT ERROR] RVA 0x%x actual=0x%08x expected=0x%08x\n",
                       DURAK_RATE_PROMPT_RVA + i * 4, word, expected);
      durak_log_flush();
      return -2;
    }
  }
  return 0;
}

int durak_patch_rate_prompt(void *staging, size_t size) {
  int rc = check_rate_prompt(staging, size, 0);
  if (rc) return rc;
  uint32_t ret = 0xd65f03c0;
  memcpy((char *)staging + DURAK_RATE_PROMPT_RVA, &ret, 4);
  durak_log_printf("[RATE PROMPT] WindowsInvoker.InvokeRateWnd disabled\n");
  durak_log_flush();
  return 0;
}

int durak_verify_rate_prompt(const void *mapped, size_t size) {
  int rc = check_rate_prompt(mapped, size, 1);
  if (!rc) durak_log_printf("[RATE PROMPT OK] Rating prompt disabled in RX image\n");
  durak_log_flush();
  return rc;
}

static int check_free_key_prompt(const void *base, size_t size, int patched) {
  if (!base || size < DURAK_FREE_KEY_PROMPT_RVA + sizeof(DURAK_FREE_KEY_PROMPT_CONTEXT)) return -1;
  for (int i = 0; i < 5; ++i) {
    uint32_t word;
    memcpy(&word, (const char *)base + DURAK_FREE_KEY_PROMPT_RVA + i * 4, 4);
    uint32_t expected = patched && i == 0 ? 0xd65f03c0 : DURAK_FREE_KEY_PROMPT_CONTEXT[i];
    if (word != expected) {
      durak_log_printf("[FREE KEY PROMPT ERROR] RVA 0x%x actual=0x%08x expected=0x%08x\n",
                       DURAK_FREE_KEY_PROMPT_RVA + i * 4, word, expected);
      durak_log_flush();
      return -2;
    }
  }
  return 0;
}

int durak_patch_free_key_prompt(void *staging, size_t size) {
  int rc = check_free_key_prompt(staging, size, 0);
  if (rc) return rc;
  uint32_t ret = 0xd65f03c0;
  memcpy((char *)staging + DURAK_FREE_KEY_PROMPT_RVA, &ret, 4);
  durak_log_printf("[FREE KEY PROMPT] WindowsInvoker.InvokeFreeKeyWnd disabled\n");
  durak_log_flush();
  return 0;
}

int durak_verify_free_key_prompt(const void *mapped, size_t size) {
  int rc = check_free_key_prompt(mapped, size, 1);
  if (!rc) durak_log_printf("[FREE KEY PROMPT OK] Free key prompt disabled in RX image\n");
  durak_log_flush();
  return rc;
}

static int check_single_game_unlock(const void *base, size_t size, int patched) {
  if (!base) return -1;
  for (int i = 0; i < DURAK_SINGLE_GAME_UNLOCK_N; ++i) {
    const DurakSingleGameUnlock *site = &DURAK_SINGLE_GAME_UNLOCK[i];
    if (site->off > size || size - site->off < sizeof(site->context)) return -1;
    for (int j = 0; j < 5; ++j) {
      uint32_t actual;
      memcpy(&actual, (const char *)base + site->off + j * 4, sizeof(actual));
      uint32_t expected = patched && j == 1 ? site->unlocked : site->context[j];
      if (actual != expected) {
        durak_log_printf("[SINGLE UNLOCK ERROR] RVA 0x%x: actual=0x%08x expected=0x%08x\n",
                         site->off + j * 4, actual, expected);
        durak_log_flush();
        return -2;
      }
    }
  }
  return 0;
}

int durak_patch_single_game_unlock(void *staging, size_t size) {
  int rc = check_single_game_unlock(staging, size, 0);
  if (rc) return rc; /* Check every site before changing any byte. */
  for (int i = 0; i < DURAK_SINGLE_GAME_UNLOCK_N; ++i) {
    const DurakSingleGameUnlock *site = &DURAK_SINGLE_GAME_UNLOCK[i];
    memcpy((char *)staging + site->off + 4, &site->unlocked, sizeof(site->unlocked));
    durak_log_printf("[SINGLE UNLOCK] RVA 0x%x: 0x%08x -> 0x%08x\n",
                     site->off + 4, site->context[1], site->unlocked);
  }
  durak_log_flush();
  return 0;
}

int durak_verify_single_game_unlock(const void *mapped, size_t size) {
  int rc = check_single_game_unlock(mapped, size, 1);
  if (!rc) durak_log_printf("[SINGLE UNLOCK OK] 3 level checks disabled in RX image; statistics preserved\n");
  durak_log_flush();
  return rc;
}

int durak_patch_unity_regions(void *staging_load_base, size_t load_size) {
  if (!staging_load_base) return -1;

  durak_log_printf("\n[REGION PATCH] Checking 18 allocator granularity sites in libunity staging image...\n");

  // Pass 1: Strict Verification of all 18 sites before making ANY modifications.
  // Fail-closed: If ANY instruction doesn't match 'from', do not patch anything!
  for (int i = 0; i < DURAK_REGION_PATCH_N; i++) {
    uint32_t off = DURAK_REGION_PATCH[i].off;
    if (off + 4 > load_size) {
      durak_log_printf("[REGION ERROR] Site %d RVA 0x%x exceeds libunity load size 0x%zx!\n",
                       i + 1, off, load_size);
      durak_log_flush();
      return -1;
    }
    uint32_t cur = *(volatile uint32_t *)((uintptr_t)staging_load_base + off);
    if (cur != DURAK_REGION_PATCH[i].from) {
      durak_log_printf("[REGION ERROR] Site %d [%s] @ RVA 0x%x mismatch:\n"
                       "  Expected: 0x%08x\n"
                       "  Actual:   0x%08x\n"
                       "  -> FAIL CLOSED: refusing to patch mismatched binary!\n",
                       i + 1, DURAK_REGION_PATCH[i].desc, off,
                       DURAK_REGION_PATCH[i].from, cur);
      durak_log_flush();
      return -2;
    }
  }

  // Pass 2: Apply all 18 patches to writable staging image
  durak_log_printf("[REGION PATCH] All 18 instructions confirmed. Applying 256MB -> 64MB transforms:\n");
  for (int i = 0; i < DURAK_REGION_PATCH_N; i++) {
    uint32_t off = DURAK_REGION_PATCH[i].off;
    *(volatile uint32_t *)((uintptr_t)staging_load_base + off) = DURAK_REGION_PATCH[i].to;
    durak_log_printf("  [%2d/18] RVA 0x%06x: 0x%08x -> 0x%08x (%s)\n",
                     i + 1, off, DURAK_REGION_PATCH[i].from, DURAK_REGION_PATCH[i].to,
                     DURAK_REGION_PATCH[i].desc);
  }

  durak_log_printf("[REGION PATCH OK] 18/18 sites successfully patched in staging buffer.\n\n");
  durak_log_flush();
  return 0;
}

int durak_verify_unity_regions_post_map(const void *virtbase, size_t load_size) {
  if (!virtbase) return -1;

  durak_log_printf("[REGION POST-CHECK] Verifying 18 patched sites in CodeMemory @ %p...\n", virtbase);
  for (int i = 0; i < DURAK_REGION_PATCH_N; i++) {
    uint32_t off = DURAK_REGION_PATCH[i].off;
    if (off + 4 > load_size) return -1;
    uint32_t cur = *(volatile uint32_t *)((uintptr_t)virtbase + off);
    if (cur != DURAK_REGION_PATCH[i].to) {
      durak_log_printf("[REGION ERROR] Post-check failed @ RVA 0x%x: have 0x%08x, expected 0x%08x!\n",
                       off, cur, DURAK_REGION_PATCH[i].to);
      durak_log_flush();
      return -1;
    }
  }

  durak_log_printf("[REGION POST-CHECK OK] All 18 sites confirmed active in executable memory (RX).\n\n");
  durak_log_flush();
  return 0;
}

int durak_patch_unity_choreographer(void *staging_load_base, size_t load_size) {
  if (!staging_load_base) return -1;

  durak_log_printf("[CHOREO PATCH] Checking ChoreographerBase::Get entry in libunity staging image...\n");

  // Pass 1: Strict Verification before making ANY modifications.
  // Fail-closed: If ANY instruction doesn't match 'from', do not patch anything!
  for (int i = 0; i < DURAK_CHOREOGRAPHER_PATCH_N; i++) {
    uint32_t off = DURAK_CHOREOGRAPHER_PATCH[i].off;
    if (off + 4 > load_size) {
      durak_log_printf("[CHOREO ERROR] Site %d RVA 0x%x exceeds libunity load size 0x%zx!\n",
                       i + 1, off, load_size);
      durak_log_flush();
      return -1;
    }
    uint32_t cur = *(volatile uint32_t *)((uintptr_t)staging_load_base + off);
    if (cur != DURAK_CHOREOGRAPHER_PATCH[i].from) {
      durak_log_printf("[CHOREO ERROR] Site %d [%s] @ RVA 0x%x mismatch:\n"
                       "  Expected: 0x%08x\n"
                       "  Actual:   0x%08x\n"
                       "  -> FAIL CLOSED: refusing to patch mismatched binary!\n",
                       i + 1, DURAK_CHOREOGRAPHER_PATCH[i].desc, off,
                       DURAK_CHOREOGRAPHER_PATCH[i].from, cur);
      durak_log_flush();
      return -2;
    }
  }

  // Pass 2: Apply patch to writable staging image
  durak_log_printf("[CHOREO PATCH] Both instructions confirmed. Applying ChoreographerBase::Get -> NULL fallback:\n");
  for (int i = 0; i < DURAK_CHOREOGRAPHER_PATCH_N; i++) {
    uint32_t off = DURAK_CHOREOGRAPHER_PATCH[i].off;
    *(volatile uint32_t *)((uintptr_t)staging_load_base + off) = DURAK_CHOREOGRAPHER_PATCH[i].to;
    durak_log_printf("  [%d/2] RVA 0x%06x: 0x%08x -> 0x%08x (%s)\n",
                     i + 1, off, DURAK_CHOREOGRAPHER_PATCH[i].from, DURAK_CHOREOGRAPHER_PATCH[i].to,
                     DURAK_CHOREOGRAPHER_PATCH[i].desc);
  }

  durak_log_printf("[CHOREO PATCH OK] ChoreographerBase::Get fallback patched successfully in staging buffer.\n\n");
  durak_log_flush();
  return 0;
}

int durak_verify_unity_choreographer_post_map(const void *virtbase, size_t load_size) {
  if (!virtbase) return -1;

  durak_log_printf("[CHOREO POST-CHECK] Verifying ChoreographerBase::Get fallback in CodeMemory @ %p...\n", virtbase);
  for (int i = 0; i < DURAK_CHOREOGRAPHER_PATCH_N; i++) {
    uint32_t off = DURAK_CHOREOGRAPHER_PATCH[i].off;
    if (off + 4 > load_size) return -1;
    uint32_t cur = *(volatile uint32_t *)((uintptr_t)virtbase + off);
    if (cur != DURAK_CHOREOGRAPHER_PATCH[i].to) {
      durak_log_printf("[CHOREO ERROR] Post-check failed @ RVA 0x%x: have 0x%08x, expected 0x%08x!\n",
                       off, cur, DURAK_CHOREOGRAPHER_PATCH[i].to);
      durak_log_flush();
      return -1;
    }
  }

  durak_log_printf("[CHOREO POST-CHECK OK] ChoreographerBase::Get fallback confirmed active in executable memory (RX).\n\n");
  durak_log_flush();
  return 0;
}
