/* so_util.c -- utils to load and hook .so modules
 *
 * Copyright (C) 2021 Andy Nguyen, fgsfds
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * Loads Android ARM64 shared objects into a reserved memory range and applies
 * the relocation types used by libff4.so.
 */

#include <stdint.h>

#ifdef __SWITCH__
#include <switch.h>
#else
#define Perm_None 0
#define Perm_R    1
#define Perm_W    2
#define Perm_Rw   3
#define Perm_X    4
#define Perm_Rx   5
typedef uint32_t Result;
#define R_FAILED(res)   ((res) != 0)
#define R_SUCCEEDED(res) ((res) == 0)
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <pthread.h>
#include <elf.h>

#include "config.h"
#include "boot_measure.h"
#include "so_util.h"
#include "util.h"
#include "error.h"
#include "durak_target_verify.h"
#include "fail_stop_thunks.h"

// not in devkitA64's elf.h
#ifndef DT_RELR
#define DT_RELR    36
#define DT_RELRSZ  35
#define DT_RELRENT 37
#endif
#define DT_ANDROID_RELR    0x6fffe000
#define DT_ANDROID_RELRSZ  0x6fffe001
#define DT_ANDROID_RELRENT 0x6fffe003

static so_module *so_list = NULL;

static so_virtmem_find_fn   g_virtmem_find_hook = NULL;
static so_virtmem_add_fn    g_virtmem_add_hook = NULL;
static so_virtmem_remove_fn g_virtmem_remove_hook = NULL;

void so_set_virtmem_hooks(so_virtmem_find_fn find_fn, so_virtmem_add_fn add_fn, so_virtmem_remove_fn remove_fn) {
  g_virtmem_find_hook = find_fn;
  g_virtmem_add_hook = add_fn;
  g_virtmem_remove_hook = remove_fn;
}

void hook_arm64(uintptr_t addr, uintptr_t dst) {
  if (addr == 0)
    return;
  uint32_t *hook = (uint32_t *)addr;
  hook[0] = 0x58000051u; // LDR X17, #0x8
  hook[1] = 0xd61f0220u; // BR X17
  *(uint64_t *)(hook + 2) = dst;
}

void so_flush_caches(so_module *mod) {
#ifdef __SWITCH__
  armDCacheFlush(mod->load_virtbase, mod->load_size);
  armICacheInvalidate(mod->load_virtbase, mod->load_size);
#else
  (void)mod;
#endif
}

void so_free_temp(so_module *mod) {
  free(mod->so_base);
  mod->so_base = NULL;
}

void so_finalize(so_module *mod) {
#ifdef __SWITCH__
  Result rc = 0;

  // Map the entire module as CodeMemory (initially Perm_None)
  rc = svcMapProcessCodeMemory(envGetOwnProcessHandle(), (u64)mod->load_virtbase, (u64)mod->load_base, mod->load_size);
  if (R_FAILED(rc)) fatal_error("Error: svcMapProcessCodeMemory failed:\n%08x", rc);

  // Kernel allows transitions from Perm_None to Perm_Rx, Perm_R, Perm_Rw on CodeMemory.
  // Transitions from W -> X are strictly forbidden (0xD801).
  // 3-Tier W^X Permission Scheme:
  // 1 = Perm_Rx (executable code)
  // 2 = Perm_R  (read-only data, headers, and RELRO)
  // 3 = Perm_Rw (writable data, BSS, and alignment gaps)
  const size_t num_pages = mod->load_size / 0x1000;
  uint8_t *page_perm = calloc(num_pages, 1);
  if (!page_perm) fatal_error("Error: out of memory in so_finalize");

  // Pass A: Identify PT_LOAD segment permissions
  for (int i = 0; i < mod->phnum; i++) {
    const Elf64_Phdr *p = &mod->phdr[i];
    if (p->p_type != PT_LOAD)
      continue;
    const size_t first = p->p_vaddr / 0x1000;
    const size_t last = (ALIGN_MEM(p->p_vaddr + p->p_memsz, 0x1000) / 0x1000) - 1;
    for (size_t pg = first; pg <= last && pg < num_pages; pg++) {
      if (p->p_flags & PF_X) {
        page_perm[pg] = 1; // RX
      } else if (p->p_flags & PF_W) {
        if (page_perm[pg] != 1) page_perm[pg] = 3; // RW
      } else {
        if (page_perm[pg] == 0) page_perm[pg] = 2; // R
      }
    }
  }

  // Pass B: Identify PT_GNU_RELRO segment (lock down to read-only post-reloc)
  for (int i = 0; i < mod->phnum; i++) {
    const Elf64_Phdr *p = &mod->phdr[i];
    if (p->p_type != PT_GNU_RELRO)
      continue;
    const size_t first = p->p_vaddr / 0x1000;
    const size_t last = ((p->p_vaddr + p->p_memsz) / 0x1000);
    for (size_t pg = first; pg < last && pg < num_pages; pg++) {
      if (page_perm[pg] != 1) { // Do not touch RX
        page_perm[pg] = 2; // R
      }
    }
  }

  // Apply permissions in strict order:
  // Pass 1: RX (fresh from Perm_None)
  // Pass 2: R  (read-only data & RELRO)
  // Pass 3: RW (writable data & inter-segment gaps)
  for (int pass = 1; pass <= 3; pass++) {
    u32 target_perm = (pass == 1) ? Perm_Rx : ((pass == 2) ? Perm_R : Perm_Rw);
    size_t pg = 0;
    while (pg < num_pages) {
      int match = (pass == 3) ? (page_perm[pg] == 3 || page_perm[pg] == 0) : (page_perm[pg] == pass);
      if (!match) {
        pg++;
        continue;
      }
      size_t run_end = pg;
      while (run_end < num_pages) {
        int run_match = (pass == 3) ? (page_perm[run_end] == 3 || page_perm[run_end] == 0) : (page_perm[run_end] == pass);
        if (!run_match) break;
        run_end++;
      }
      const u64 addr = (u64)mod->load_virtbase + pg * 0x1000;
      const u64 size = (run_end - pg) * 0x1000;
      rc = svcSetProcessMemoryPermission(envGetOwnProcessHandle(), addr, size, target_perm);
      if (R_FAILED(rc)) {
        fatal_error("Error: could not map %u bytes of %s memory at %p:\n%08x",
                    (u32)size, (pass == 1) ? "RX" : ((pass == 2) ? "RO" : "RW"), (void *)addr, rc);
      }
      pg = run_end;
    }
  }

  free(page_perm);

  // svcMapProcessCodeMemory donates the source pages (load_base) to the code
  // mapping; afterwards load_base is in CodeMemory state and faults on access --
  // the image is readable only via load_virtbase. mod->syms/dynstrtab were set to
  // load_base for pre-finalize import resolution (when load_virtbase isn't mapped
  // yet). Rebase them to load_virtbase now so post-finalize lookups (dlsym ->
  // so_lookup_export, e.g. libunity resolving il2cpp_init) read the live mapped
  // .dynsym/.dynstr instead of faulting on the donated source range.
  const uintptr_t delta = (uintptr_t)mod->load_virtbase - (uintptr_t)mod->load_base;
  if (mod->syms)      mod->syms      = (Elf64_Sym *)((uintptr_t)mod->syms + delta);
  if (mod->dynstrtab) mod->dynstrtab = (char *)((uintptr_t)mod->dynstrtab + delta);
#else
  (void)mod;
#endif
}

int so_load(so_module *mod, const char *filename, void *base, size_t max_size) {
  int res = 0;

  memset(mod, 0, sizeof(*mod));
  strncpy(mod->name, filename, sizeof(mod->name) - 1);

  // 1. Strict Target Metadata Check
  const DurakModuleMetadata *meta = durak_find_module_metadata(filename);
  if (!meta) {
    debugPrintf("[SECURITY] Unknown module rejected: %s\n", filename);
    return -1;
  }

  uint64_t read_begin=durak_boot_measure_now();
  FILE *fd = fopen(filename, "rb");
  if (fd == NULL)
    return -1;

  fseek(fd, 0, SEEK_END);
  mod->so_size = ftell(fd);
  fseek(fd, 0, SEEK_SET);

  mod->so_base = malloc(mod->so_size);
  if (!mod->so_base) {
    fclose(fd);
    return -2;
  }

  fread(mod->so_base, mod->so_size, 1, fd);
  fclose(fd);

  durak_boot_measure_phase("ELF_file_read_and_allocation",filename,read_begin);
  uint64_t verify_begin=durak_boot_measure_now();

  // 2. Strict SHA-256 and GNU Build-ID Target Verification
  int verify_rc=durak_verify_target_buffer(meta, mod->so_base, mod->so_size);
  durak_boot_measure_phase("ELF_SHA256_and_BuildID",filename,verify_begin);
  if (verify_rc != 0) {
    debugPrintf("[SECURITY] Target validation FAILED for %s!\n", filename);
    res = -5;
    goto err_free_so;
  }

  mod->elf_hdr = (Elf64_Ehdr *)mod->so_base;
  mod->prog_hdr = (Elf64_Phdr *)((uintptr_t)mod->so_base + mod->elf_hdr->e_phoff);
  mod->sec_hdr = (Elf64_Shdr *)((uintptr_t)mod->so_base + mod->elf_hdr->e_shoff);
  mod->shstrtab = (char *)((uintptr_t)mod->so_base + mod->sec_hdr[mod->elf_hdr->e_shstrndx].sh_offset);

  if (mod->elf_hdr->e_phnum > SO_MAX_SEGMENTS * 2) {
    debugPrintf("so_load: %s has too many program headers (%d)\n", filename, mod->elf_hdr->e_phnum);
    res = -4;
    goto err_free_so;
  }

  // save a pristine copy of the phdrs for dl_iterate_phdr
  mod->phnum = mod->elf_hdr->e_phnum;
  memcpy(mod->phdr, mod->prog_hdr, mod->phnum * sizeof(Elf64_Phdr));

  // Determine max alignment across all PT_LOAD segments (64 KiB for sqlite3, 16 KiB for others)
  size_t max_align = 0x1000;
  mod->load_size = 0;
  for (int i = 0; i < mod->elf_hdr->e_phnum; i++) {
    if (mod->prog_hdr[i].p_type == PT_LOAD) {
      if (mod->prog_hdr[i].p_align > max_align) {
        max_align = mod->prog_hdr[i].p_align;
      }
      const size_t seg_end = mod->prog_hdr[i].p_vaddr + mod->prog_hdr[i].p_memsz;
      if (seg_end > mod->load_size)
        mod->load_size = seg_end;
    }
  }
  mod->max_align = max_align;

  // Align total size to max_align
  mod->load_size = ALIGN_MEM(mod->load_size, max_align);
  if (mod->load_size > max_size) {
    res = -3;
    goto err_free_so;
  }

  mod->load_base = base;
  if (!mod->load_base) goto err_free_so;
  memset(mod->load_base, 0, mod->load_size);

  if (((uintptr_t)mod->load_base & (max_align - 1)) != 0) {
    debugPrintf("so_load: %s load_base %p is not aligned to max_align 0x%zx\n",
                filename, mod->load_base, max_align);
    res = -3;
    goto err_free_so;
  }

#ifdef __SWITCH__
  // Reserve virtual memory space for the entire LOAD zone with max_align.
  // virtmemFindCodeMemory only guarantees page alignment (0x1000). To ensure
  // max_align, we over-allocate by (max_align - 0x1000) and explicitly align
  // the resulting address upwards.
  size_t extra_align = (max_align > 0x1000) ? (max_align - 0x1000) : 0;
  size_t alloc_size = mod->load_size + extra_align;

  virtmemLock();
  void *raw_virtbase = g_virtmem_find_hook ?
                       g_virtmem_find_hook(alloc_size, 0x1000) :
                       virtmemFindCodeMemory(alloc_size, 0x1000);
  if (!raw_virtbase) {
    virtmemUnlock();
    debugPrintf("so_load: virtmem code memory search failed for %s (size=0x%zx)\n", filename, alloc_size);
    res = -6;
    goto err_free_so;
  }

  void *aligned_virtbase = (void *)ALIGN_MEM((uintptr_t)raw_virtbase, max_align);
  if (((uintptr_t)aligned_virtbase & (max_align - 1)) != 0) {
    virtmemUnlock();
    debugPrintf("so_load: failed to align virtbase %p to 0x%zx for %s\n", aligned_virtbase, max_align, filename);
    res = -6;
    goto err_free_so;
  }

  void *rv = g_virtmem_add_hook ?
             g_virtmem_add_hook(raw_virtbase, alloc_size) :
             (void *)virtmemAddReservation(raw_virtbase, alloc_size);
  if (!rv) {
    virtmemUnlock();
    debugPrintf("so_load: virtmem code memory reservation failed for %s (size=0x%zx)\n", filename, alloc_size);
    res = -6;
    goto err_free_so;
  }
  virtmemUnlock();

  mod->load_virtbase = aligned_virtbase;
  mod->load_memrv = rv;
#else
  if (g_virtmem_find_hook) {
    size_t extra_align = (max_align > 0x1000) ? (max_align - 0x1000) : 0;
    size_t alloc_size = mod->load_size + extra_align;
    void *raw_virtbase = g_virtmem_find_hook(alloc_size, 0x1000);
    if (!raw_virtbase) {
      debugPrintf("so_load: mock code memory search failed for %s (size=0x%zx)\n", filename, alloc_size);
      res = -6;
      goto err_free_so;
    }
    void *aligned_virtbase = (void *)ALIGN_MEM((uintptr_t)raw_virtbase, max_align);
    if (((uintptr_t)aligned_virtbase & (max_align - 1)) != 0) {
      debugPrintf("so_load: mock failed to align virtbase %p to 0x%zx for %s\n", aligned_virtbase, max_align, filename);
      res = -6;
      goto err_free_so;
    }
    void *rv = g_virtmem_add_hook ? g_virtmem_add_hook(raw_virtbase, alloc_size) : (void *)1;
    if (!rv) {
      debugPrintf("so_load: mock code memory reservation failed for %s\n", filename);
      res = -6;
      goto err_free_so;
    }
    mod->load_virtbase = aligned_virtbase;
    mod->load_memrv = rv;
  } else {
    mod->load_virtbase = mod->load_base;
    mod->load_memrv = NULL;
  }
#endif

  // Strict post-check: load_virtbase MUST be strictly aligned to max_align
  if (((uintptr_t)mod->load_virtbase & (max_align - 1)) != 0) {
    debugPrintf("so_load: load_virtbase %p not aligned to max_align 0x%zx for %s\n",
                mod->load_virtbase, max_align, filename);
    res = -6;
    goto err_free_load;
  }

  // copy segments to where they belong, then fix up the runtime phdrs to
  // point into the virtual address space
  for (int i = 0; i < mod->elf_hdr->e_phnum; i++) {
    Elf64_Phdr *p = &mod->prog_hdr[i];
    if (p->p_type == PT_LOAD) {
      memcpy((void *)((uintptr_t)mod->load_base + p->p_vaddr),
             (void *)((uintptr_t)mod->so_base + p->p_offset),
             p->p_filesz);
    }
    p->p_vaddr += (Elf64_Addr)mod->load_virtbase;
  }

  mod->syms = NULL;
  mod->dynstrtab = NULL;

  for (int i = 0; i < mod->elf_hdr->e_shnum; i++) {
    char *sh_name = mod->shstrtab + mod->sec_hdr[i].sh_name;
    if (strcmp(sh_name, ".dynsym") == 0) {
      mod->syms = (Elf64_Sym *)((uintptr_t)mod->load_base + mod->sec_hdr[i].sh_addr);
      mod->num_syms = mod->sec_hdr[i].sh_size / sizeof(Elf64_Sym);
    } else if (strcmp(sh_name, ".dynstr") == 0) {
      mod->dynstrtab = (char *)((uintptr_t)mod->load_base + mod->sec_hdr[i].sh_addr);
    }
  }

  if (mod->syms == NULL || mod->dynstrtab == NULL) {
    res = -2;
    goto err_free_load;
  }

  // remove if already in list to prevent circular references
  if (so_list == mod) {
    so_list = mod->next;
  } else if (so_list) {
    for (so_module *m = so_list; m->next; m = m->next) {
      if (m->next == mod) {
        m->next = mod->next;
        break;
      }
    }
  }

  // register in the global module list (append, load order matters for resolution)
  mod->next = NULL;
  if (!so_list) {
    so_list = mod;
  } else {
    so_module *m = so_list;
    while (m->next) m = m->next;
    m->next = mod;
  }

  // Discover constructor information from PT_DYNAMIC
  so_get_init_array_info(mod, NULL, NULL, NULL);

  return 0;

err_free_load:
#ifdef __SWITCH__
  if (mod->load_memrv) {
    virtmemLock();
    if (g_virtmem_remove_hook) {
      g_virtmem_remove_hook(mod->load_memrv);
    } else {
      virtmemRemoveReservation((VirtmemReservation *)mod->load_memrv);
    }
    mod->load_memrv = NULL;
    virtmemUnlock();
  }
#else
  if (mod->load_memrv && g_virtmem_remove_hook) {
    g_virtmem_remove_hook(mod->load_memrv);
    mod->load_memrv = NULL;
  }
#endif
err_free_so:
  free(mod->so_base);
  mod->so_base = NULL;

  return res;
}

// find a dynamic tag in the file image; returns 0 if missing
static Elf64_Xword so_dynamic_tag(so_module *mod, Elf64_Sxword tag) {
  for (int i = 0; i < mod->phnum; i++) {
    if (mod->phdr[i].p_type == PT_DYNAMIC) {
      const Elf64_Dyn *dyn = (const Elf64_Dyn *)((uintptr_t)mod->so_base + mod->phdr[i].p_offset);
      for (; dyn->d_tag != DT_NULL; dyn++)
        if (dyn->d_tag == tag)
          return dyn->d_un.d_val;
    }
  }
  return 0;
}

// RELR/ANDROID_RELR packed relative relocations;
// each location gets the load base added to the value stored in the file
static void so_process_relr(so_module *mod, const Elf64_Xword *relr, size_t relrsz) {
  uintptr_t where = 0;
  const size_t count = relrsz / sizeof(Elf64_Xword);
  for (size_t i = 0; i < count; i++) {
    const Elf64_Xword entry = relr[i];
    if ((entry & 1) == 0) {
      // even entry: address of the next relocation
      where = (uintptr_t)entry;
      *(uint64_t *)((uintptr_t)mod->load_base + where) += (uint64_t)mod->load_virtbase;
      where += 8;
    } else {
      // odd entry: bitmap for the next 63 words
      for (int bit = 1; bit < 64; bit++) {
        if (entry & (1ull << bit))
          *(uint64_t *)((uintptr_t)mod->load_base + where + (bit - 1) * 8) += (uint64_t)mod->load_virtbase;
      }
      where += 63 * 8;
    }
  }
}

int so_get_init_array_info(so_module *mod, uintptr_t *out_init_array_rva, size_t *out_count, uintptr_t *out_init_rva) {
  uintptr_t init_array_vaddr = so_dynamic_tag(mod, DT_INIT_ARRAY);
  size_t init_arraysz = so_dynamic_tag(mod, DT_INIT_ARRAYSZ);
  uintptr_t init_vaddr = so_dynamic_tag(mod, DT_INIT);

  mod->init_array_rva = init_array_vaddr;
  mod->init_array_count = init_arraysz / sizeof(uintptr_t);
  mod->init_rva = init_vaddr;

  if (out_init_array_rva) *out_init_array_rva = init_array_vaddr;
  if (out_count) *out_count = mod->init_array_count;
  if (out_init_rva) *out_init_rva = init_vaddr;
  return (init_arraysz > 0 || init_vaddr > 0) ? 0 : -1;
}

int so_relocate(so_module *mod) {
  mod->num_relocations = 0;
  for (int i = 0; i < mod->elf_hdr->e_shnum; i++) {
    char *sh_name = mod->shstrtab + mod->sec_hdr[i].sh_name;
    if (strcmp(sh_name, ".rela.dyn") == 0 || strcmp(sh_name, ".rela.plt") == 0) {
      Elf64_Rela *rels = (Elf64_Rela *)((uintptr_t)mod->load_base + mod->sec_hdr[i].sh_addr);
      int count = mod->sec_hdr[i].sh_size / sizeof(Elf64_Rela);
      mod->num_relocations += count;
      for (int j = 0; j < count; j++) {
        uintptr_t *ptr = (uintptr_t *)((uintptr_t)mod->load_base + rels[j].r_offset);
        Elf64_Sym *sym = &mod->syms[ELF64_R_SYM(rels[j].r_info)];

        int type = ELF64_R_TYPE(rels[j].r_info);
        switch (type) {
          case R_AARCH64_ABS64:
            if (sym->st_shndx == SHN_UNDEF) {
              // Imported absolute relocations resolved in so_resolve
              *ptr = rels[j].r_addend;
            } else {
              *ptr = (uintptr_t)mod->load_virtbase + sym->st_value + rels[j].r_addend;
            }
            break;

          case R_AARCH64_RELATIVE:
            *ptr = (uintptr_t)mod->load_virtbase + rels[j].r_addend;
            break;

          case R_AARCH64_GLOB_DAT:
          case R_AARCH64_JUMP_SLOT:
          {
            if (sym->st_shndx != SHN_UNDEF)
              *ptr = (uintptr_t)mod->load_virtbase + sym->st_value + rels[j].r_addend;
            break;
          }

          default:
            fatal_error("Error: unknown relocation type:\n%x\n", type);
            break;
        }
      }
    }
  }

  // packed relative relocations, if present (lld emits these for newer libs)
  Elf64_Xword relr_off = so_dynamic_tag(mod, DT_RELR);
  Elf64_Xword relr_size = so_dynamic_tag(mod, DT_RELRSZ);
  if (!relr_off) {
    relr_off = so_dynamic_tag(mod, DT_ANDROID_RELR);
    relr_size = so_dynamic_tag(mod, DT_ANDROID_RELRSZ);
  }
  if (relr_off && relr_size) {
    so_process_relr(mod, (const Elf64_Xword *)((uintptr_t)mod->load_base + relr_off), relr_size);
  }

  // Discover constructor information from PT_DYNAMIC
  so_get_init_array_info(mod, NULL, NULL, NULL);

  return 0;
}

// look up an exported (defined) symbol in a single module;
// returns its virtual (runtime) address or 0
static uintptr_t so_lookup_export(so_module *mod, const char *name) {
  for (int i = 0; i < mod->num_syms; i++) {
    if (mod->syms[i].st_shndx == SHN_UNDEF)
      continue;
    if (ELF64_ST_BIND(mod->syms[i].st_info) == STB_LOCAL)
      continue;
    const char *sname = mod->dynstrtab + mod->syms[i].st_name;
    if (sname[0] == name[0] && strcmp(sname, name) == 0)
      return (uintptr_t)mod->load_virtbase + mod->syms[i].st_value;
  }
  return 0;
}

// dlsym() backing: search every loaded module's exports for `name`.
void *so_resolve_external(const char *name) {
  if (!name)
    return NULL;
  for (so_module *m = so_list; m; m = m->next) {
    const uintptr_t addr = so_lookup_export(m, name);
    if (addr)
      return (void *)addr;
  }
  return NULL;
}

so_module *so_find_module_by_addr(const void *addr) {
  const uintptr_t a = (uintptr_t)addr;
  for (so_module *m = so_list; m; m = m->next) {
    const uintptr_t base = (uintptr_t)m->load_virtbase;
    if (a >= base && a < base + m->load_size)
      return m;
  }
  return NULL;
}

int so_dump_maps(char *buf, size_t cap) {
  if (!buf || cap == 0) return 0;
  size_t off = 0;
  for (so_module *m = so_list; m; m = m->next) {
    uintptr_t s = (uintptr_t)m->load_virtbase;
    uintptr_t e = s + m->load_size;
    int n = snprintf(buf + off, cap - off,
                     "%012lx-%012lx r-xp 00000000 00:00 0          %s\n",
                     (unsigned long)s, (unsigned long)e, m->name[0] ? m->name : "module");
    if (n < 0 || (size_t)n >= cap - off) break;
    off += (size_t)n;
  }
  buf[off < cap ? off : cap - 1] = '\0';
  return (int)off;
}

static uintptr_t so_resolve_symbol(so_module *mod, DynLibFunction *funcs, int num_funcs, const char *name, int *out_is_cross) {
  if (out_is_cross) *out_is_cross = 0;
  // Prefer Switch shims over exports from other loaded modules.
  for (int k = 0; k < num_funcs; k++) {
    if (strcmp(name, funcs[k].symbol) == 0)
      return funcs[k].func;
  }

  for (so_module *m = so_list; m; m = m->next) {
    if (m == mod)
      continue;
    const uintptr_t addr = so_lookup_export(m, name);
    if (addr) {
      if (out_is_cross) *out_is_cross = 1;
      return addr;
    }
  }

  return 0;
}

int so_resolve(so_module *mod, DynLibFunction *funcs, int num_funcs, int taint_missing_imports) {
  (void)taint_missing_imports; // Poisoning is eliminated and replaced with fail-stop thunks
  int fatal_missing = 0;

  for (int i = 0; i < mod->elf_hdr->e_shnum; i++) {
    char *sh_name = mod->shstrtab + mod->sec_hdr[i].sh_name;
    if (strcmp(sh_name, ".rela.dyn") == 0 || strcmp(sh_name, ".rela.plt") == 0) {
      Elf64_Rela *rels = (Elf64_Rela *)((uintptr_t)mod->load_base + mod->sec_hdr[i].sh_addr);
      for (int j = 0; j < mod->sec_hdr[i].sh_size / sizeof(Elf64_Rela); j++) {
        uintptr_t *ptr = (uintptr_t *)((uintptr_t)mod->load_base + rels[j].r_offset);
        Elf64_Sym *sym = &mod->syms[ELF64_R_SYM(rels[j].r_info)];

        int type = ELF64_R_TYPE(rels[j].r_info);
        switch (type) {
          case R_AARCH64_ABS64:
          case R_AARCH64_GLOB_DAT:
          case R_AARCH64_JUMP_SLOT:
          {
            if (sym->st_shndx == SHN_UNDEF) {
              char *name = mod->dynstrtab + sym->st_name;
              int is_cross = 0;
              uintptr_t addr = so_resolve_symbol(mod, funcs, num_funcs, name, &is_cross);

              if (addr) {
                *ptr = addr + rels[j].r_addend;
                if (is_cross) {
                  mod->num_resolved_cross++;
                } else {
                  mod->num_resolved_shims++;
                }
              } else {
                uint8_t bind = ELF64_ST_BIND(sym->st_info);
                uint8_t st_type = ELF64_ST_TYPE(sym->st_info);

                if (bind == STB_WEAK) {
                  // Weak undefined symbol: resolve to NULL (0) per ELF semantics
                  *ptr = 0;
                  mod->num_weak_null++;
                  debugPrintf("[RESOLVE] %s: weak undefined symbol '%s' -> NULL (0)\n", mod->name, name);
                } else if (st_type == STT_FUNC || type == R_AARCH64_JUMP_SLOT) {
                  // Strong function import: bind to static ABI-safe fail-stop thunk
                  uintptr_t thunk_addr = 0;
                  if (durak_register_fail_stop_function(mod->name, name, &thunk_addr) == 0) {
                    *ptr = thunk_addr;
                    mod->num_fail_stop++;
                    debugPrintf("[RESOLVE] %s: strong unresolved function '%s' -> fail-stop thunk %p\n",
                                mod->name, name, (void *)thunk_addr);
                  } else {
                    fatal_error("[RESOLVE] %s: fail-stop thunk pool exhausted for '%s'!\n", mod->name, name);
                  }
                } else {
                  // Strong data symbol: HALT AUDIT (cannot be thunked!)
                  fatal_missing++;
                  mod->num_strong_data_unresolved++;
                  debugPrintf("[FATAL AUDIT] %s: unresolved strong data symbol '%s'!\n", mod->name, name);
                }
              }
            }
            break;
          }

          default:
            break;
        }
      }
    }
  }

  if (fatal_missing) {
    debugPrintf("%s: %d fatal unresolved strong data symbols\n", mod->name, fatal_missing);
    return -1;
  }

  return 0;
}

int so_execute_init_array(so_module *mod) {
  if (!mod || !mod->load_virtbase) return -1;

  uint64_t tid = 0;
#ifdef __SWITCH__
  svcGetThreadId(&tid, CUR_THREAD_HANDLE);
#else
  tid = (uint64_t)pthread_self();
#endif

  durak_log_printf("[INIT] Starting constructors for %s (virtbase=%p, dt_init=0x%lx, ctors=%zu, tid=%llu)...\n",
                   mod->name, mod->load_virtbase, (unsigned long)mod->init_rva,
                   mod->init_array_count, (unsigned long long)tid);
  durak_log_flush();

  typedef void (*init_func_t)(void);

  // 1. DT_INIT (if present)
  if (mod->init_rva) {
    uintptr_t init_fn_addr = (uintptr_t)mod->load_virtbase + mod->init_rva;
    durak_log_printf("[DT_INIT BEGIN] mod=%s rva=0x%lx addr=%p tid=%llu\n",
                     mod->name, (unsigned long)mod->init_rva, (void *)init_fn_addr, (unsigned long long)tid);
    durak_log_flush();

#ifdef __aarch64__
    init_func_t init_fn = (init_func_t)init_fn_addr;
    init_fn();
#endif

    durak_log_printf("[DT_INIT END] mod=%s rva=0x%lx returned tid=%llu\n",
                     mod->name, (unsigned long)mod->init_rva, (unsigned long long)tid);
    durak_log_flush();
  }

  // 2. DT_INIT_ARRAY
  if (mod->init_array_rva && mod->init_array_count > 0) {
    uintptr_t *init_array = (uintptr_t *)((uintptr_t)mod->load_virtbase + mod->init_array_rva);
    size_t count = mod->init_array_count;

    durak_log_printf("[INIT] Executing %zu ctors from .init_array for %s @ %p\n",
                     count, mod->name, (void *)init_array);
    durak_log_flush();

    for (size_t j = 0; j < count; j++) {
      uintptr_t fn_addr = init_array[j];
      if (fn_addr == 0 || fn_addr == (uintptr_t)-1) {
        durak_log_printf("[CTOR SKIP] mod=%s [%zu/%zu] null or -1\n", mod->name, j + 1, count);
        durak_log_flush();
        continue;
      }

      uintptr_t rva = 0;
      if (fn_addr >= (uintptr_t)mod->load_virtbase &&
          fn_addr < (uintptr_t)mod->load_virtbase + mod->load_size) {
        rva = fn_addr - (uintptr_t)mod->load_virtbase;
      }

      durak_log_printf("[CTOR BEGIN] mod=%s [%zu/%zu] rva=0x%lx addr=%p tid=%llu\n",
                       mod->name, j + 1, count, (unsigned long)rva, (void *)fn_addr, (unsigned long long)tid);
      /* Known-good constructor sequence: batch BEGIN/END records through the
       * logger's 250 ms sync interval. Module boundaries remain durable.
       * An abrupt crash may lose the last buffered constructor records. */

#ifdef __aarch64__
      init_func_t ctor = (init_func_t)fn_addr;
      ctor();
#endif

      durak_log_printf("[CTOR END] mod=%s [%zu/%zu] returned tid=%llu\n",
                       mod->name, j + 1, count, (unsigned long long)tid);
    }
  }

  durak_log_printf("[INIT OK] mod=%s: all %zu constructors completed successfully\n",
                   mod->name, mod->init_array_count);
  durak_log_flush();
  return 0;
}

uintptr_t so_find_addr(so_module *mod, const char *symbol) {
  for (int i = 0; i < mod->num_syms; i++) {
    char *name = mod->dynstrtab + mod->syms[i].st_name;
    if (strcmp(name, symbol) == 0)
      return (uintptr_t)mod->load_base + mod->syms[i].st_value;
  }

  fatal_error("Error: could not find symbol:\n%s\n", symbol);
  return 0;
}

uintptr_t so_find_addr_rx(so_module *mod, const char *symbol) {
  const uintptr_t addr = so_try_find_addr_rx(mod, symbol);
  if (!addr)
    fatal_error("Error: could not find symbol:\n%s\n", symbol);
  return addr;
}

uintptr_t so_try_find_addr_rx(so_module *mod, const char *symbol) {
  for (int i = 0; i < mod->num_syms; i++) {
    char *name = mod->dynstrtab + mod->syms[i].st_name;
    if (strcmp(name, symbol) == 0)
      return (uintptr_t)mod->load_virtbase + mod->syms[i].st_value;
  }
  return 0;
}

DynLibFunction *so_find_import(DynLibFunction *funcs, int num_funcs, const char *name) {
  for (int i = 0; i < num_funcs; ++i)
    if (!strcmp(funcs[i].symbol, name))
      return &funcs[i];
  return NULL;
}

int so_unload(so_module *mod) {
  if (mod->load_base == NULL)
    return -1;

  if (mod->so_base) {
    // someone forgot to free the temp data
    so_free_temp(mod);
  }

#ifdef __SWITCH__
  // remap everything as RW
  for (int i = 0; i < mod->phnum; i++) {
    const Elf64_Phdr *p = &mod->phdr[i];
    if (p->p_type != PT_LOAD || !(p->p_flags & PF_X))
      continue;
    const u64 seg_start = ((u64)mod->load_virtbase + p->p_vaddr) & ~0xFFFull;
    const u64 seg_end = ALIGN_MEM((u64)mod->load_virtbase + p->p_vaddr + p->p_memsz, 0x1000);
    svcSetProcessMemoryPermission(envGetOwnProcessHandle(), seg_start, seg_end - seg_start, Perm_Rw);
  }
  // unmap everything
  svcUnmapProcessCodeMemory(envGetOwnProcessHandle(), (u64)mod->load_virtbase, (u64)mod->load_base, mod->load_size);

  // release virtual address range
  if (mod->load_memrv) {
    virtmemLock();
    if (g_virtmem_remove_hook) {
      g_virtmem_remove_hook(mod->load_memrv);
    } else {
      virtmemRemoveReservation((VirtmemReservation *)mod->load_memrv);
    }
    mod->load_memrv = NULL;
    virtmemUnlock();
  }
#else
  if (mod->load_memrv && g_virtmem_remove_hook) {
    g_virtmem_remove_hook(mod->load_memrv);
    mod->load_memrv = NULL;
  }
#endif

  // remove from list
  if (so_list == mod) {
    so_list = mod->next;
  } else {
    for (so_module *m = so_list; m; m = m->next) {
      if (m->next == mod) {
        m->next = mod->next;
        break;
      }
    }
  }

  return 0;
}

void so_reset_list(void) {
  so_list = NULL;
}

// matches the layout bionic/libunwind expect
struct so_dl_phdr_info {
  Elf64_Addr dlpi_addr;
  const char *dlpi_name;
  const Elf64_Phdr *dlpi_phdr;
  Elf64_Half dlpi_phnum;
};

int so_dl_iterate_phdr(int (*callback)(void *info, size_t size, void *data), void *data) {
  int ret = 0;
  for (so_module *mod = so_list; mod; mod = mod->next) {
    struct so_dl_phdr_info info;
    info.dlpi_addr = (Elf64_Addr)mod->load_virtbase;
    info.dlpi_name = mod->name;
    info.dlpi_phdr = mod->phdr; // link-time vaddrs + dlpi_addr = runtime
    info.dlpi_phnum = mod->phnum;
    ret = callback(&info, sizeof(info), data);
    if (ret)
      break;
  }
  return ret;
}

/* ------------------------------------------------------------------------- */
/* Neutralize bionic TLS stack-canary checks in a loaded module.
 *
 * The engine reads its stack guard from tpidr_el0+0x28, but it installs its own
 * bionic TLS partway through init, so a function that runs across that swap sees
 * a different guard at exit than it saved at entry and calls __stack_chk_fail
 * (a false positive -- the stack isn't actually corrupted). We can't keep the
 * guard perfectly consistent through the engine's own TLS management, so instead
 * we patch the check: find the canary epilogue and NOP the conditional branch to
 * the fail block, so it always falls through to the normal return.
 *
 * Pattern (AArch64):
 *    ldr  Xt, [Xn, #0x28]      ; live guard  (imm12 == 5)
 *    ldr  Xs, [sp, #imm]       ; saved canary
 *    ... (0-4 insns) ...
 *    b.ne <fail>               ; <- NOP this
 *  <fail> contains a bl __stack_chk_fail within a few insns (confirmation).
 *
 * Must run while the code is still writable (load_base), before so_finalize.
 */
void so_patch_stack_canaries(so_module *mod) {
  // Step 2 invariant: Blanket NOP patching of stack canaries is inhibited
  // unless specific target evidence proves a false-positive canary failure.
  debugPrintf("[patch] %s: stack canary patching inhibited (no target evidence)\n", mod->name);
}

// ---------------------------------------------------------------------------
// Runtime code patcher. Module text is mapped RX at load_virtbase (via
// svcMapProcessCodeMemory) and is not writable. Create a temporary writable
// alias of the containing pages with svcMapProcessMemory, write through it,
// unmap, and flush caches. Returns 0 on success. Used to hook/replace specific
// il2cpp methods that gate boot (no source recompilation available).
int so_patch_code(void *dst, const void *src, size_t len) {
#ifdef __SWITCH__
  uintptr_t start = (uintptr_t)dst & ~0xFFFull;
  size_t maplen = ((((uintptr_t)dst + len) - start) + 0xFFF) & ~0xFFFull;
  size_t off = (uintptr_t)dst - start;
  virtmemLock();
  void *alias = virtmemFindAslr(maplen, 0);
  VirtmemReservation *rv = alias ? virtmemAddReservation(alias, maplen) : NULL;
  virtmemUnlock();
  if (!alias) { debugPrintf("[patch] no aslr slot\n"); return -1; }
  Result rc = svcMapProcessMemory(alias, envGetOwnProcessHandle(), (u64)start, maplen);
  if (R_FAILED(rc)) {
    virtmemLock(); if (rv) virtmemRemoveReservation(rv); virtmemUnlock();
    debugPrintf("[patch] svcMapProcessMemory %p<-0x%lx (%zu) failed rc=%08x\n",
                alias, (unsigned long)start, maplen, rc);
    return -2;
  }
  memcpy((uint8_t *)alias + off, src, len);
  svcUnmapProcessMemory(alias, envGetOwnProcessHandle(), (u64)start, maplen);
  virtmemLock(); if (rv) virtmemRemoveReservation(rv); virtmemUnlock();
  armDCacheFlush(dst, len);
  armICacheInvalidate(dst, len);
  debugPrintf("[patch] ok %p (%zu bytes)\n", dst, len);
  return 0;
#else
  memcpy(dst, src, len);
  return 0;
#endif
}
