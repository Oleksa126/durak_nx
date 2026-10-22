#include "static_catalog.h"
#include "static_catalog_data.h"
#include "so_util.h"
#include "util.h"
#include <string.h>

uintptr_t durak_static_table_continue, durak_static_row_continue, durak_static_text_continue;
#ifdef __aarch64__
extern void durak_static_table_guard(void),durak_static_row_guard(void),durak_static_text_guard(void);
#else
/* Native verification does not execute patched ARM64 code. */
void durak_static_table_guard(void) {}
void durak_static_row_guard(void) {}
void durak_static_text_guard(void) {}
#endif
typedef struct { uint32_t rva; const uint32_t *words; uintptr_t destination; uintptr_t *continuation; } Hook;
static Hook hooks[]={
  {DURAK_STATIC_TABLE_RVA,catalog_table_fingerprint,(uintptr_t)durak_static_table_guard,&durak_static_table_continue},
  {DURAK_STATIC_ROW_RVA,catalog_row_fingerprint,(uintptr_t)durak_static_row_guard,&durak_static_row_continue},
  {DURAK_STATIC_TEXT_RVA,catalog_text_fingerprint,(uintptr_t)durak_static_text_guard,&durak_static_text_continue},
};
typedef struct { uint32_t rva,words[4],replacement; } Cleanup;
static const Cleanup cleanup[]={
  /* OnEnable: skip only marketing counter, retain both redraws. */
  {0xd7af2c,{0x90007335,0xaa1403e0,0xaa1f03e2,0xf94602b5},0x14000012},
  /* After redrawDiffButtons, enter the original active-tab selection. */
  {0xd7af84,{0xf94002c8,0xf9405d08,0xf9400108,0xb4001208},0x14000079},
  /* All premium marketing banners, void(instance,int,MethodInfo*). */
  {0xcf607c,{0xd100c3ff,0xa90157fe,0xa9024ff4,0x90008734},0xd65f03c0},
  /* updateUserBlock: retain G.O in x22; skip premium_end/date/log work.
   * Its time-dependent companion offer tail is removed below as well. */
  {0xd6efe0,{0x940d74d5,0xaa0003e1,0x910023e0,0xaa1f03e2},0x14000038},
  /* All profile/currency/cup refreshes precede this offer-only tail.
   * Use the original hide-companion-offer path and balanced epilogue. */
  {0xd6f640,{0xf94002c8,0xf9405d08,0xf9400108,0xb4001308},0x14000086},
  /* Existing scene row: do not increment marketing openings or UPDATE it.
   * Missing-row/first_run initialization remains for daily-reward dates. */
  {0xd8f718,{0xb4000d68,0xf9400300,0xf9401d14,0x97f9523e},0x14000064},
  /* Offline commerce/advertising entry points return void. A leaf RET
   * consumes no arguments (including MethodInfo*) and changes no stack. */
  {0xd8f8c8,{0xd105c3ff,0xfd0083e8,0xa9117bfd,0xa9126ffc},0xd65f03c0}, /* ShowSpecialOffer */
  {0xd6d57c,{0xf81c0ffe,0xa9015ff8,0xa90257f6,0xa9034ff4},0xd65f03c0}, /* GetADID */
  {0xd6cf1c,{0xd10143ff,0xa90167fe,0xa9025ff8,0xa90357f6},0xd65f03c0}, /* OnNoAdsPurchase */
  {0xd6dac0,{0xf81d0ffe,0xa90157f6,0xa9024ff4,0xb0008374},0xd65f03c0}, /* ShowAlternatePayment */
  {0xd6e280,{0xf81d0ffe,0xa90157f6,0xa9024ff4,0x90008374},0xd65f03c0}, /* buttonPremium */
  {0xd7032c,{0xf81c0ffe,0xa9015ff8,0xa90257f6,0xa9034ff4},0xd65f03c0}, /* buyPremium(bool) */
  {0xd72ecc,{0xa9be57fe,0xa9014ff4,0x90008354,0xb0007355},0xd65f03c0}, /* PremiumWindowController.buyPremium */
  {0xd88680,{0xa9be57fe,0xa9014ff4,0xd0008294,0xf0007295},0xd65f03c0}, /* PremiumWindow.buyPremium */
};
static int check(so_module *mod,const void *base,int patched) {
  if(!mod || !base)return -1;
  for(size_t h=0;h<sizeof(hooks)/sizeof(hooks[0]);++h) {
    Hook *hook=&hooks[h];
    if(hook->rva>mod->load_size || mod->load_size-hook->rva<32)return -1;
    uint32_t expected[8]; memcpy(expected,hook->words,32);
    if(patched) { expected[0]=0x58000051;expected[1]=0xd61f0220;memcpy(expected+2,&hook->destination,8); }
    if(memcmp((const char *)base+hook->rva,expected,32)) {
      durak_log_printf("[STATIC DATA ERROR] managed boundary fingerprint RVA=0x%x; refuse patch\n",hook->rva); return -2;
    }
  }
  for(size_t i=0;i<sizeof(cleanup)/sizeof(cleanup[0]);++i) {
    const Cleanup *p=&cleanup[i]; uint32_t expected[4]; memcpy(expected,p->words,16);
    if(p->rva>mod->load_size || mod->load_size-p->rva<16)return -1;
    if(patched)expected[0]=p->replacement;
    if(memcmp((const char *)base+p->rva,expected,16)) {
      durak_log_printf("[STATIC DATA ERROR] offline cleanup fingerprint RVA=0x%x; refuse patch\n",p->rva); return -3;
    }
  }
  return 0;
}
int durak_static_patch(so_module *mod) {
  int rc=check(mod,mod ? mod->load_base : NULL,0); if(rc)return rc;
  DurakStaticApi bindings={0};
#define BIND(member,name) do { uintptr_t p=so_find_addr_rx(mod,name); if(!p) { durak_log_printf("[STATIC DATA ERROR] missing %s\n",name); return -4; } memcpy(&bindings.member,&p,sizeof(p)); } while(0)
  BIND(method_return_type,"il2cpp_method_get_return_type"); BIND(class_from_type,"il2cpp_class_from_type");
  BIND(object_class,"il2cpp_object_get_class"); BIND(element_class,"il2cpp_class_get_element_class");
  BIND(parent_class,"il2cpp_class_get_parent"); BIND(class_name,"il2cpp_class_get_name");
  BIND(class_namespace,"il2cpp_class_get_namespace"); BIND(field,"il2cpp_class_get_field_from_name");
  BIND(field_type,"il2cpp_field_get_type"); BIND(type_kind,"il2cpp_type_get_type");
  BIND(field_get,"il2cpp_field_get_value"); BIND(field_set,"il2cpp_field_set_value");
  BIND(object_new,"il2cpp_object_new"); BIND(array_new,"il2cpp_array_new");
  BIND(array_header,"il2cpp_array_object_header_size"); BIND(barrier,"il2cpp_gc_wbarrier_set_field");
  BIND(root,"il2cpp_gchandle_new"); BIND(root_get,"il2cpp_gchandle_get_target");
  BIND(root_free,"il2cpp_gchandle_free"); BIND(string_new,"il2cpp_string_new");
  BIND(string_length,"il2cpp_string_length"); BIND(string_chars,"il2cpp_string_chars");
#undef BIND
  durak_static_bind(&bindings);
  for(size_t i=0;i<sizeof(hooks)/sizeof(hooks[0]);++i) {
    *hooks[i].continuation=(uintptr_t)mod->load_virtbase+hooks[i].rva+16;
    hook_arm64((uintptr_t)mod->load_base+hooks[i].rva,hooks[i].destination);
  }
  for(size_t i=0;i<sizeof(cleanup)/sizeof(cleanup[0]);++i)
    memcpy((char *)mod->load_base+cleanup[i].rva,&cleanup[i].replacement,4);
  return 0;
}
int durak_static_verify(so_module *mod) { return check(mod,mod ? mod->load_virtbase : NULL,1); }
