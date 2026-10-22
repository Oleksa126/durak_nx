/* unity_input_hook.c -- Fail-closed Switch touchscreen & pointer hooks for Durak 25.0
 *
 * Target: Android ARM64 ru.appscraft.durak v25.0 (Unity 6 / IL2CPP)
 * libil2cpp.so Build-ID: d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0
 *
 * Intercepts UnityEngine.Input managed entrypoints to feed Switch touchscreen
 * and controller virtual cursor directly into Unity 6's EventSystem / UI.
 *
 * Features:
 *  - 100% Structural Durak RVAs with fail-closed instruction fingerprint verification
 *  - Exact AAPCS64 value-type return ABI for UnityEngine.Touch (indirect sret in x8, 0x44 bytes)
 *  - Exact AAPCS64 HFA return ABI for UnityEngine.Vector3 (s0, s1, s2)
 *  - Full state-machine transitions: Began (0), Moved (1), Stationary (2), Ended (3)
 *  - Button down/up 1-frame edge triggers for GetMouseButtonDown(0) and GetMouseButtonUp(0)
 *  - Clean transition logging without frame-by-frame spam
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <stdatomic.h>

#include "unity_input_hook.h"
#include "util.h"
#include "so_util.h"
#include "boot_screen.h"

extern int screen_width, screen_height;

/* No managed object is retained between frames. Reflection runs only inside
 * Unity's managed Input callback, after its domain and scripting thread exist.
 * Button.Press checks active/interactable and invokes the original onClick.
 * These paths are the serialized uGUI menu buttons in Durak 25.0 level4,
 * level6/10 and Klondike level5; no main-menu/puzzle exit buttons are included. */
static atomic_int g_menu_requested;
static void *(*menu_domain_get)(void);
static void *(*menu_assembly_open)(void *, const char *);
static void *(*menu_assembly_image)(void *);
static void *(*menu_class_from_name)(void *, const char *, const char *);
static void *(*menu_method)(void *, const char *, int);
static void *(*menu_class_type)(void *);
static void *(*menu_type_object)(void *);
static void *(*menu_string)(const char *);
static void *(*menu_invoke)(void *, void *, void **, void **);
static void *(*menu_thread_current)(void);
static void (*menu_format_exception)(void *, char *, int);
static int g_menu_ready;

int nx_input_menu_init(so_module *module) {
#define MENU_API(dst, symbol) do { \
  uintptr_t address = so_find_addr_rx(module, symbol); \
  _Static_assert(sizeof(dst) == sizeof(address), "function pointer size"); \
  memcpy(&dst, &address, sizeof(dst)); \
  if (!dst) { durak_log_printf("[INPUT MENU] Missing export %s\n", symbol); return -1; } \
} while (0)
  g_menu_ready = 0;
  MENU_API(menu_domain_get, "il2cpp_domain_get");
  MENU_API(menu_assembly_open, "il2cpp_domain_assembly_open");
  MENU_API(menu_assembly_image, "il2cpp_assembly_get_image");
  MENU_API(menu_class_from_name, "il2cpp_class_from_name");
  MENU_API(menu_method, "il2cpp_class_get_method_from_name");
  MENU_API(menu_class_type, "il2cpp_class_get_type");
  MENU_API(menu_type_object, "il2cpp_type_get_object");
  MENU_API(menu_string, "il2cpp_string_new");
  MENU_API(menu_invoke, "il2cpp_runtime_invoke");
  MENU_API(menu_thread_current, "il2cpp_thread_current");
  MENU_API(menu_format_exception, "il2cpp_format_exception");
#undef MENU_API
  g_menu_ready = 1;
  return 0;
}

void nx_input_menu_request(void) {
  atomic_store(&g_menu_requested, 1);
}

static void *menu_call(void *method, void *object, void **args, int *failed) {
  void *exception = NULL;
  void *result = menu_invoke(method, object, args, &exception);
  if (exception) {
    char message[512] = {0};
    menu_format_exception(exception, message, sizeof(message));
    durak_log_printf("[INPUT MENU] Managed exception: %s\n", message);
    durak_log_flush();
    *failed = 1;
  }
  return result;
}

static void nx_input_menu_dispatch(void) {
  if (!atomic_exchange(&g_menu_requested, 0)) return;
  if (!g_menu_ready || !menu_thread_current()) {
    durak_log_printf("[INPUT MENU] Plus ignored: scripting API/thread unavailable\n");
    return;
  }
  void *domain = menu_domain_get();
  void *core = domain ? menu_assembly_open(domain, "UnityEngine.CoreModule") : NULL;
  void *ui = domain ? menu_assembly_open(domain, "UnityEngine.UI") : NULL;
  void *go_class = core ? menu_class_from_name(menu_assembly_image(core), "UnityEngine", "GameObject") : NULL;
  void *button_class = ui ? menu_class_from_name(menu_assembly_image(ui), "UnityEngine.UI", "Button") : NULL;
  void *find = go_class ? menu_method(go_class, "Find", 1) : NULL;
  void *component = go_class ? menu_method(go_class, "GetComponent", 1) : NULL;
  void *press = button_class ? menu_method(button_class, "Press", 0) : NULL;
  if (!find || !component || !press) {
    durak_log_printf("[INPUT MENU] Plus ignored: uGUI reflection contract missing\n");
    return;
  }
  const char *paths[] = {"GUI Layer/Widescreen/Menu Button",
                        "GUI Layer/Ipad/Menu Button", "Screen/GUILayer/MenuButton"};
  int failed = 0;
  for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {
    void *name = menu_string(paths[i]);
    void *args[] = {name};
    void *go = menu_call(find, NULL, args, &failed);
    if (failed) return;
    if (!go) continue; /* GameObject.Find returns only active scene objects. */
    args[0] = menu_type_object(menu_class_type(button_class));
    void *button = menu_call(component, go, args, &failed);
    if (failed) return;
    if (!button) continue;
    menu_call(press, button, NULL, &failed);
    if (!failed) durak_log_printf("[INPUT MENU] Plus -> Button.Press: %s\n", paths[i]);
    return;
  }
  durak_log_printf("[INPUT MENU] Plus: no active game menu button\n");
}

static void nx_input_check_main_menu(void) {
  static unsigned queries;
  if (!boot_screen_waiting() || !g_menu_ready || ++queries % 15 != 0 || !menu_thread_current()) return;
  void *domain=menu_domain_get();
  void *assembly=domain ? menu_assembly_open(domain,"UnityEngine.CoreModule") : NULL;
  void *klass=assembly ? menu_class_from_name(menu_assembly_image(assembly),"UnityEngine","GameObject") : NULL;
  void *find=klass ? menu_method(klass,"Find",1) : NULL;
  if(!find) return;
  void *name=menu_string("MainMenu");
  void *args[]={name};
  int failed=0;
  void *go=menu_call(find,NULL,args,&failed);
  if(!failed && go) boot_screen_menu_ready();
}

/* ---- Touch & Pointer State ---- */
static int   g_hook_count = 0;                        /* Input.touchCount (0 or 1)                        */
static int   g_hook_btn = 0;                          /* Input.GetMouseButton(0) (held)                   */
static int   g_hook_btn_down = 0, g_hook_btn_up = 0;  /* 1-frame edge triggers                            */
static int   g_hook_phase = 3;                        /* TouchPhase: 0=Began, 1=Moved, 2=Stat, 3=Ended    */
static float g_hook_x = 0.0f, g_hook_y = 0.0f;        /* Unity screen space (bottom-left origin, px)      */
static float g_hook_dx = 0.0f, g_hook_dy = 0.0f;      /* Position delta (px)                              */

/* Query APIs for verification / diagnostic tests */
int   nx_input_hook_get_count(void)    { return g_hook_count; }
int   nx_input_hook_get_btn(void)      { return g_hook_btn; }
int   nx_input_hook_get_btn_down(void) { return g_hook_btn_down; }
int   nx_input_hook_get_btn_up(void)   { return g_hook_btn_up; }
int   nx_input_hook_get_phase(void)    { return g_hook_phase; }
void  nx_input_hook_get_pos(float *x, float *y) {
  if (x) *x = g_hook_x;
  if (y) *y = g_hook_y;
}

/* ---- Unity value types & AAPCS64 return rules ---- */
typedef struct { float x, y; }    NxV2;
typedef struct { float x, y, z; } NxV3;                 /* 12-byte HFA -> returned in s0, s1, s2 */

/* UnityEngine.Touch layout verified from global-metadata.dat v39 (total size 0x44 / 68 bytes) */
typedef struct {
  int32_t m_FingerId;                 /* 0x00: int32                             */
  NxV2    m_Position;                 /* 0x04: Vector2 (x @ 0x04, y @ 0x08)      */
  NxV2    m_RawPosition;              /* 0x0c: Vector2 (x @ 0x0c, y @ 0x10)      */
  NxV2    m_PositionDelta;            /* 0x14: Vector2 (x @ 0x14, y @ 0x18)      */
  float   m_TimeDelta;                /* 0x1c: float                             */
  int32_t m_TapCount;                 /* 0x20: int32                             */
  int32_t m_Phase;                    /* 0x24: int32 TouchPhase (0..4)           */
  int32_t m_Type;                     /* 0x28: int32 TouchType (0=Direct)        */
  float   m_Pressure;                 /* 0x2c: float                             */
  float   m_maxPressure;              /* 0x30: float                             */
  float   m_Radius;                   /* 0x34: float                             */
  float   m_RadiusVariance;           /* 0x38: float                             */
  float   m_AltitudeAngle;            /* 0x3c: float (radians)                   */
  float   m_AzimuthAngle;             /* 0x40: float (radians)                   */
} NxTouch;                            /* > 16 bytes -> returned indirectly via x8 (sret) */

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(NxTouch) == 0x44, "NxTouch must be exactly 0x44 (68) bytes to match IL2CPP layout");
#endif

/* ---- IL2CPP Hook Entrypoints ----
 * Calling convention:
 * Static methods in IL2CPP take (args..., MethodInfo* mi).
 */
static int32_t hk_touchCount(void *mi) {
  (void)mi;
  nx_input_check_main_menu();
  nx_input_menu_dispatch();
  return g_hook_count;
}

static NxTouch hk_getTouch(int32_t index, void *mi) {
  (void)mi;
  NxTouch t;
  memset(&t, 0, sizeof(t));
  if (index == 0 && g_hook_count > 0) {
    t.m_FingerId = 0;
    t.m_Position.x = g_hook_x;
    t.m_Position.y = g_hook_y;
    t.m_RawPosition = t.m_Position;
    t.m_PositionDelta.x = g_hook_dx;
    t.m_PositionDelta.y = g_hook_dy;
    t.m_TimeDelta = 0.016666f;
    t.m_TapCount = 1;
    t.m_Phase = g_hook_phase;
    t.m_Type = 0; // Direct touch
    t.m_Pressure = 1.0f;
    t.m_maxPressure = 1.0f;
    t.m_Radius = 1.0f;
    t.m_RadiusVariance = 0.0f;
    t.m_AltitudeAngle = 1.5707963f; // PI/2
    t.m_AzimuthAngle = 0.0f;
  }
  return t;
}

static NxV3 hk_mousePosition(void *mi) {
  nx_input_check_main_menu();
  (void)mi;
  NxV3 v = { g_hook_x, g_hook_y, 0.0f };
  return v;
}

static uint8_t hk_getMouseButton(int32_t b, void *mi) {
  (void)mi;
  return (b == 0) ? (uint8_t)g_hook_btn : 0;
}

static uint8_t hk_getMouseButtonDown(int32_t b, void *mi) {
  (void)mi;
  return (b == 0) ? (uint8_t)g_hook_btn_down : 0;
}

static uint8_t hk_getMouseButtonUp(int32_t b, void *mi) {
  (void)mi;
  return (b == 0) ? (uint8_t)g_hook_btn_up : 0;
}

static uint8_t hk_touchSupported(void *mi) {
  (void)mi;
  return 1;
}

static uint8_t hk_mousePresent(void *mi) {
  (void)mi;
  return 1;
}

/* Site definition for fail-closed verification and trampoline installation */
typedef struct {
  const char *name;
  uintptr_t  rva;
  void       *hook_fn;
  uint32_t   expected_insn0;
  uint32_t   expected_insn1;
} InputHookSite;

static const InputHookSite g_input_sites[] = {
  { "get_touchCount",     DURAK_RVA_get_touchCount,     (void *)hk_touchCount,        0xa9bf4ffe, 0xd0002cf3 },
  { "GetTouch",           DURAK_RVA_GetTouch,           (void *)hk_getTouch,          0xd101c3ff, 0xa90557fe },
  { "get_mousePosition",  DURAK_RVA_get_mousePosition,  (void *)hk_mousePosition,     0xd10083ff, 0xa9014ffe },
  { "GetMouseButton",     DURAK_RVA_GetMouseButton,     (void *)hk_getMouseButton,    0xf81e0ffe, 0xa9014ff4 },
  { "GetMouseButtonDown", DURAK_RVA_GetMouseButtonDown, (void *)hk_getMouseButtonDown,0xf81e0ffe, 0xa9014ff4 },
  { "GetMouseButtonUp",   DURAK_RVA_GetMouseButtonUp,   (void *)hk_getMouseButtonUp,  0xf81e0ffe, 0xa9014ff4 },
  { "get_touchSupported", DURAK_RVA_get_touchSupported, (void *)hk_touchSupported,   0xa9bf4ffe, 0xd0002cf3 },
  { "get_mousePresent",   DURAK_RVA_get_mousePresent,   (void *)hk_mousePresent,     0xa9bf4ffe, 0xf0002cf3 },
};

int nx_install_input_hooks(uintptr_t il2cpp_base) {
  if (!il2cpp_base) {
    durak_log_printf("[INPUT ERROR] il2cpp_base is NULL\n");
    durak_log_flush();
    return -1;
  }

  size_t count = sizeof(g_input_sites) / sizeof(g_input_sites[0]);
  durak_log_printf("[INPUT] Checking %zu Input hook sites in libil2cpp.so...\n", count);
  durak_log_flush();

  /* 1. Fail-closed pre-check: verify all 8 sites have exact expected instructions */
  for (size_t i = 0; i < count; i++) {
    const InputHookSite *site = &g_input_sites[i];
    uintptr_t addr = il2cpp_base + site->rva;
    uint32_t actual[2];
    memcpy(actual, (const void *)addr, sizeof(actual));
    if (actual[0] != site->expected_insn0 || actual[1] != site->expected_insn1) {
      durak_log_printf("[INPUT ERROR] Site [%zu/%zu] %s @ RVA 0x%lx mismatch:\n"
                       "  Expected: 0x%08x 0x%08x\n"
                       "  Actual:   0x%08x 0x%08x\n"
                       "  -> FAIL CLOSED: refusing to patch mismatched binary!\n",
                       i + 1, count, site->name, (unsigned long)site->rva,
                       site->expected_insn0, site->expected_insn1,
                       actual[0], actual[1]);
      durak_log_flush();
      return -2;
    }
  }

  /* 2. Apply patches with verified trampolines:
   *   ldr x16, #8
   *   br  x16
   *   .quad target
   */
  for (size_t i = 0; i < count; i++) {
    const InputHookSite *site = &g_input_sites[i];
    uintptr_t addr = il2cpp_base + site->rva;
    uint32_t code[4];
    code[0] = 0x58000050u; /* ldr x16, #8 */
    code[1] = 0xd61f0200u; /* br  x16       */
    void *target = site->hook_fn;
    memcpy(&code[2], &target, sizeof(target));

    int rc = so_patch_code((void *)addr, code, sizeof(code));
    if (rc != 0) {
      durak_log_printf("[INPUT ERROR] so_patch_code failed for %s @ RVA 0x%lx (rc=%d)\n",
                       site->name, (unsigned long)site->rva, rc);
      durak_log_flush();
      return -3;
    }
    durak_log_printf("[INPUT OK] [%zu/%zu] Patched %s @ RVA 0x%lx -> %p\n",
                     i + 1, count, site->name, (unsigned long)site->rva, target);
  }
  durak_log_flush();

  /* 3. Post-check verification in CodeMemory */
  for (size_t i = 0; i < count; i++) {
    const InputHookSite *site = &g_input_sites[i];
    uintptr_t addr = il2cpp_base + site->rva;
    uint32_t actual[2];
    memcpy(actual, (const void *)addr, sizeof(actual));
    if (actual[0] != 0x58000050u || actual[1] != 0xd61f0200u) {
      durak_log_printf("[INPUT ERROR] Post-check failed for %s @ RVA 0x%lx: 0x%08x 0x%08x\n",
                       site->name, (unsigned long)site->rva, actual[0], actual[1]);
      durak_log_flush();
      return -4;
    }
  }

  durak_log_printf("[INPUT OK] All %zu input hooks confirmed active in libil2cpp.so!\n", count);
  durak_log_flush();
  return 0;
}

void nx_input_hook_update(int active, float ux, float uy, float raw_x, float raw_y) {
  static int prev_active = 0;
  static float last_x = 0.0f, last_y = 0.0f;
  static uint32_t touch_frames = 0;

  g_hook_btn_down = (active && !prev_active);
  g_hook_btn_up   = (!active && prev_active);

  if (active) {
    g_hook_count = 1;
    g_hook_btn = 1;
    g_hook_x = ux;
    g_hook_y = uy;

    if (!prev_active) {
      /* Touch BEGAN */
      g_hook_phase = 0; /* Began */
      g_hook_dx = 0.0f;
      g_hook_dy = 0.0f;
      touch_frames = 1;

    } else {
      /* Touch HELD / MOVED */
      float dx = ux - last_x;
      float dy = uy - last_y;
      g_hook_dx = dx;
      g_hook_dy = dy;
      if (dx * dx + dy * dy > 0.25f) {
        g_hook_phase = 1; /* Moved */
      } else {
        g_hook_phase = 2; /* Stationary */
      }
      touch_frames++;
    }
    last_x = ux;
    last_y = uy;
  } else if (prev_active) {
    /* Touch ENDED: reported for exactly ONE frame with count=1, btn_up=1, Phase=Ended */
    g_hook_count = 1;
    g_hook_btn = 0;
    g_hook_phase = 3; /* Ended */
    g_hook_dx = 0.0f;
    g_hook_dy = 0.0f;
    g_hook_x = last_x;
    g_hook_y = last_y;

    touch_frames = 0;
  } else {
    /* IDLE */
    g_hook_count = 0;
    g_hook_btn = 0;
    g_hook_phase = 3; /* Ended */
    g_hook_dx = 0.0f;
    g_hook_dy = 0.0f;
  }

  prev_active = active;
}
