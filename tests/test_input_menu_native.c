/* Exercise reflection dispatch and failure/re-entry without executing ARM64. */
#include <assert.h>
#include "../source/unity_input_hook.c"

int screen_width = 1280, screen_height = 720;
void durak_log_printf(const char *fmt, ...) { (void)fmt; }
int durak_log_flush(void) { return 0; }
uintptr_t so_find_addr_rx(so_module *m, const char *s) { (void)m; (void)s; return 0; }
int so_patch_code(void *d, const void *s, size_t n) { memcpy(d, s, n); return 0; }

static int present, throws, presses, finds;
static int loading, menu_seen;
int boot_screen_waiting(void) { return loading; }
void boot_screen_menu_ready(void) { menu_seen=1; loading=0; }
static void *domain(void) { return (void *)1; }
static void *assembly(void *d, const char *n) { assert(d); (void)n; return (void *)2; }
static void *image(void *a) { assert(a); return (void *)3; }
static void *klass(void *i, const char *ns, const char *n) {
  assert(i); (void)ns; (void)n; return (void *)4;
}
static void *method(void *k, const char *n, int count) {
  assert(k);
  if (!strcmp(n, "Find")) { assert(count == 1); return (void *)10; }
  if (!strcmp(n, "GetComponent")) { assert(count == 1); return (void *)11; }
  assert(!strcmp(n, "Press") && count == 0); return (void *)12;
}
static void *identity(void *v) { return v; }
static void *string(const char *s) { return (void *)s; }
static void format(void *e, char *b, int n) { assert(e); snprintf(b, n, "test exception"); }
static void *invoke(void *m, void *o, void **args, void **exception) {
  if (m == (void *)10) {
    assert(!o && args && args[0]); ++finds;
    if (throws) { *exception = (void *)99; return NULL; }
    return present ? (void *)20 : NULL;
  }
  if (m == (void *)11) { assert(o == (void *)20 && args[0]); return (void *)21; }
  assert(m == (void *)12 && o == (void *)21 && !args);
  ++presses;
  hk_touchCount(NULL); /* onClick may query Input: do not dispatch twice. */
  return NULL;
}

int main(void) {
  assert(nx_input_menu_init(NULL) == -1);
  menu_domain_get = domain; menu_thread_current = domain;
  menu_assembly_open = assembly; menu_assembly_image = image;
  menu_class_from_name = klass; menu_method = method;
  menu_class_type = identity; menu_type_object = identity;
  menu_string = string; menu_invoke = invoke; menu_format_exception = format;
  g_menu_ready = 1;
  nx_input_menu_request(); hk_touchCount(NULL);
  assert(finds == 3 && presses == 0); /* Main menu/loading: no action. */
  present = 1;
  nx_input_menu_request(); hk_touchCount(NULL); hk_touchCount(NULL);
  assert(presses == 1); /* One edge, one native onClick, including re-entry. */
  throws = 1;
  nx_input_menu_request(); hk_touchCount(NULL);
  assert(presses == 1); /* Preserve/report exception, don't invoke another button. */
  throws=0; loading=1; present=0;
  for(int i=0;i<15;++i) hk_touchCount(NULL);
  assert(!menu_seen);
  present=1;
  for(int i=0;i<15;++i) hk_touchCount(NULL);
  assert(menu_seen && !loading);
  puts("[PASS] Plus dispatch: inactive scene, edge, re-entry, managed exception");
  return 0;
}
