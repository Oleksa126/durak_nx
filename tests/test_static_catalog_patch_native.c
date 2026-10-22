#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../source/static_catalog_patch.c"
static const char *missing;
void durak_log_printf(const char *fmt,...) {(void)fmt;}
void durak_static_bind(const DurakStaticApi *api) {(void)api;}
uintptr_t so_find_addr_rx(so_module *module,const char *name){(void)module;return missing && !strcmp(missing,name) ? 0 : 0x12345678;}
void hook_arm64(uintptr_t addr,uintptr_t dst){uint32_t *p=(void *)addr;p[0]=0x58000051;p[1]=0xd61f0220;memcpy(p+2,&dst,8);}
int main(void) {
  so_module mod={.load_size=0xdd65a0+64};mod.load_base=calloc(1,mod.load_size);mod.load_virtbase=mod.load_base;
  assert(mod.load_base);
  for(size_t i=0;i<sizeof(hooks)/sizeof(hooks[0]);++i)memcpy((char *)mod.load_base+hooks[i].rva,hooks[i].words,32);
  for(size_t i=0;i<sizeof(cleanup)/sizeof(cleanup[0]);++i)memcpy((char *)mod.load_base+cleanup[i].rva,cleanup[i].words,16);
  char *snapshot=malloc(mod.load_size);memcpy(snapshot,mod.load_base,mod.load_size);
  for(size_t i=0;i<sizeof(cleanup)/sizeof(cleanup[0]);++i) {
    /* A mismatch at ANY site must leave ALL hooks and cleanup words intact. */
    ((char *)mod.load_base)[cleanup[i].rva+12]^=1;
    char *bad=malloc(mod.load_size);memcpy(bad,mod.load_base,mod.load_size);
    assert(durak_static_patch(&mod)<0 && !memcmp(mod.load_base,bad,mod.load_size));
    free(bad);memcpy(mod.load_base,snapshot,mod.load_size);
  }
  missing="il2cpp_gc_wbarrier_set_field";assert(durak_static_patch(&mod)<0 && !memcmp(mod.load_base,snapshot,mod.load_size));missing=NULL;
  assert(durak_static_patch(&mod)==0 && durak_static_verify(&mod)==0);
  char *patched=malloc(mod.load_size);memcpy(patched,mod.load_base,mod.load_size);
  for(size_t i=0;i<sizeof(cleanup)/sizeof(cleanup[0]);++i) {
    ((char *)mod.load_base)[cleanup[i].rva+4]^=1;
    assert(durak_static_verify(&mod)<0);
    memcpy(mod.load_base,patched,mod.load_size);
  }
  free(patched);
  assert(durak_static_table_continue==(uintptr_t)mod.load_virtbase+DURAK_STATIC_TABLE_RVA+16);
  ((char *)mod.load_base)[hooks[1].rva+8]^=1;assert(durak_static_verify(&mod)<0);
  free(snapshot);free(mod.load_base);
  puts("compiled catalog patches: atomic rejection, missing API, post-map code and continuations passed");
}
