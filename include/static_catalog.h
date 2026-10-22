#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct { const char *field; int kind; } DurakStaticColumn;
typedef union { int32_t i; float f; const char *s; } DurakStaticCell;
typedef struct {
  const char *ns, *name;
  size_t rows, cols;
  const DurakStaticColumn *columns;
  const DurakStaticCell *cells;
} DurakStaticTable;
/* x0/x1 AAPCS64 aggregate return: NULL is a valid handled translation. */
typedef struct { void *value; uintptr_t handled; } DurakStaticResult;
/* Target Unity 6 GC handles encode a pointer-sized slot, not a 32-bit index.
 * gchandle_get_target/free mask X0, then dereference the 64-bit block address. */
typedef uintptr_t DurakGcHandle;
_Static_assert(sizeof(DurakGcHandle)==8,"Durak ARM64 GC handle ABI");
typedef struct {
  void *(*method_return_type)(const void *);
  void *(*class_from_type)(const void *);
  void *(*object_class)(void *);
  void *(*element_class)(void *);
  void *(*parent_class)(void *);
  const char *(*class_name)(void *);
  const char *(*class_namespace)(void *);
  void *(*field)(void *, const char *);
  const void *(*field_type)(void *);
  int (*type_kind)(const void *);
  void (*field_get)(void *, void *, void *);
  /* Target SetValueRaw receives dereference=false: references use the object
   * itself (including NULL); primitives use the address of their value bytes. */
  void (*field_set)(void *, void *, void *);
  void *(*object_new)(void *);
  void *(*array_new)(void *, uintptr_t);
  uint32_t (*array_header)(void);
  void (*barrier)(void *, void **, void *);
  DurakGcHandle (*root)(void *, int);
  void *(*root_get)(DurakGcHandle);
  void (*root_free)(DurakGcHandle);
  void *(*string_new)(const char *);
  int32_t (*string_length)(void *);
  const uint16_t *(*string_chars)(void *);
} DurakStaticApi;
void durak_static_bind(const DurakStaticApi *api);
DurakStaticResult durak_static_table(void *manager, const void *method);
DurakStaticResult durak_static_row(void *manager, int32_t id, const void *method);
DurakStaticResult durak_static_text(void *manager, void *key, const void *method);
struct so_module;
int durak_static_patch(struct so_module *module);
int durak_static_verify(struct so_module *module);
