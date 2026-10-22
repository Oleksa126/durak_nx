/* Original catalogs compiled into the host; managed progress paths stay live. */
#include "static_catalog.h"
#include "static_catalog_data.h"
#include "util.h"
#include <errno.h>
#include <pthread.h>
#include <string.h>

static DurakStaticApi api;
static pthread_mutex_t catalog_lock=PTHREAD_MUTEX_INITIALIZER;
/* Generic translations only. Runtime strings are held by GC handles, never
 * by unregistered native pointers. Different languages have separate handles. */
static DurakGcHandle texts[235][2];
void durak_static_bind(const DurakStaticApi *bindings) { api=*bindings; }
static void *field(void *cls,const char *name) {
  for(;cls;cls=api.parent_class(cls)) { void *f=api.field(cls,name); if(f)return f; }
  return NULL;
}
static const DurakStaticTable *table_for(void *cls,size_t *index) {
  if(!cls)return NULL;
  const char *ns=api.class_namespace(cls),*name=api.class_name(cls);
  if(!ns || !name)return NULL;
  for(size_t i=0;i<DURAK_STATIC_TABLE_COUNT;++i)
    if(!strcmp(ns,catalog_tables[i].ns) && !strcmp(name,catalog_tables[i].name)) {
      if(index)*index=i;
      return &catalog_tables[i];
    }
  return NULL;
}
static int shape(void *cls,const DurakStaticTable *table,void **fields) {
  for(size_t i=0;i<table->cols;++i) {
    fields[i]=field(cls,table->columns[i].field);
    if(!fields[i] || api.type_kind(api.field_type(fields[i]))!=table->columns[i].kind) {
      durak_log_printf("[STATIC DATA ERROR] field mismatch %s.%s %s; use original method\n",
                       table->ns,table->name,table->columns[i].field);
      return 0;
    }
  }
  return 1;
}
static void **items(void *array) { return (void **)((char *)array+api.array_header()); }
static int set_reference(void *object,void *f,void *value) {
  /* Verify the target setter's actual stored reference before releasing any
   * construction root or exposing the object to managed list consumers. */
  api.field_set(object,f,value);
  void *stored=NULL; api.field_get(object,f,&stored);
  if(stored==value)return 1;
  durak_log_printf("[STATIC DATA ERROR] reference readback mismatch expected=%p stored=%p; use original method\n",value,stored);
  return 0;
}
static void *build_list(void *list_cls,void *row_cls,const DurakStaticTable *table) {
  void *fields[16];
  if(table->cols>16 || !shape(row_cls,table,fields))return NULL;
  void *items_field=field(list_cls,"_items"),*size_field=field(list_cls,"_size"),*version_field=field(list_cls,"_version");
  if(!items_field || !size_field || !version_field || api.type_kind(api.field_type(size_field))!=8 || api.type_kind(api.field_type(version_field))!=8)return NULL;
  /* Verified target List<T> and row constructors only establish zero/default
   * fields. Populate the same final field state using the public GC-aware API. */
  void *list=api.object_new(list_cls); if(!list)return NULL;
  DurakGcHandle list_root=api.root(list,1);
  if(!list_root)return NULL;
  void *array=api.array_new(row_cls,table->rows);
  if(!array) { api.root_free(list_root); return NULL; }
  if(!set_reference(list,items_field,array)) { api.root_free(list_root); return NULL; }
  for(size_t r=0;r<table->rows;++r) {
    void *row=api.object_new(row_cls);
    if(!row) { api.root_free(list_root); return NULL; }
    api.barrier(array,&items(array)[r],row); /* root before allocating strings */
    for(size_t c=0;c<table->cols;++c) {
      const DurakStaticCell *value=&table->cells[r*table->cols+c];
      if(table->columns[c].kind==14) {
        void *str=value->s ? api.string_new(value->s) : NULL;
        if(value->s && !str) { api.root_free(list_root); return NULL; }
        if(!set_reference(row,fields[c],str)) { api.root_free(list_root); return NULL; }
      } else {
        api.field_set(row,fields[c],(void *)value);
      }
    }
  }
  int32_t length=(int32_t)table->rows;
  api.field_set(list,size_field,&length);
  api.field_set(list,version_field,&length);
  /* Preserve independent lists/rows: callers may sort, clear or edit a result.
   * Only immutable localized strings are cached, never caller-owned lists. */
  api.root_free(list_root);
  return list;
}
DurakStaticResult durak_static_table(void *manager,const void *method) {
  int saved=errno;
  DurakStaticResult result={0};
  if(!manager || !method || !api.method_return_type)goto done;
  void *list_cls=api.class_from_type(api.method_return_type(method));
  if(!list_cls || strcmp(api.class_namespace(list_cls),"System.Collections.Generic") || strcmp(api.class_name(list_cls),"List`1"))goto done;
  void *f=field(list_cls,"_items"); if(!f)goto done;
  void *array_cls=api.class_from_type(api.field_type(f)); if(!array_cls)goto done;
  void *row_cls=api.element_class(array_cls);
  const DurakStaticTable *table=table_for(row_cls,NULL); if(!table)goto done;
  result.value=build_list(list_cls,row_cls,table);
  result.handled=result.value!=NULL;
done:
  errno=saved; return result;
}
DurakStaticResult durak_static_row(void *manager,int32_t id,const void *method) {
  int saved=errno;
  DurakStaticResult result={0};
  if(!manager || !method || !api.method_return_type)goto done;
  void *cls=api.class_from_type(api.method_return_type(method));
  const DurakStaticTable *table=table_for(cls,NULL); if(!table)goto done;
  size_t r;
  for(r=0;r<table->rows;++r)if(table->cells[r*table->cols].i==id)break;
  if(r==table->rows)goto done; /* Original managed missing-row exception. */
  void *fields[16];
  if(table->cols>16 || !shape(cls,table,fields))goto done;
  void *row=api.object_new(cls); if(!row)goto done;
  DurakGcHandle root=api.root(row,1); if(!root)goto done;
  for(size_t c=0;c<table->cols;++c) {
    const DurakStaticCell *v=&table->cells[r*table->cols+c];
    if(table->columns[c].kind==14) {
      void *str=v->s ? api.string_new(v->s) : NULL;
      if(v->s && !str) { api.root_free(root); goto done; }
      if(!set_reference(row,fields[c],str)) { api.root_free(root); goto done; }
    } else api.field_set(row,fields[c],(void *)v);
  }
  result.value=row; result.handled=1;
  api.root_free(root);
done:
  errno=saved; return result;
}
DurakStaticResult durak_static_text(void *manager,void *key,const void *method) {
  (void)method;
  int saved=errno;
  DurakStaticResult result={0};
  if(!manager || !key || !api.string_length)goto done;
  int n=api.string_length(key); char name[256];
  if(n<0 || n>=(int)sizeof(name))goto done;
  const uint16_t *chars=api.string_chars(key);
  for(int i=0;i<n;++i) { if(chars[i]>127)goto done; name[i]=(char)chars[i]; }
  name[n]=0;
  void *lang_field=field(api.object_class(manager),"loclang"); if(!lang_field)goto done;
  int32_t lang; api.field_get(manager,lang_field,&lang);
  int language=lang==10 ? 0 : lang==30 ? 1 : -1; if(language<0)goto done;
  const DurakStaticTable *table=NULL;
  for(size_t t=0;t<DURAK_STATIC_TABLE_COUNT;++t)
    if(!strcmp(catalog_tables[t].ns,"L10nTypes") && !strcmp(catalog_tables[t].name,"Generic"))table=&catalog_tables[t];
  if(!table || table->rows>235)goto done;
  size_t r;
  for(r=0;r<table->rows;++r)if(!strcmp(table->cells[r*table->cols+1].s,name))break;
  if(r==table->rows)goto done; /* Preserve the original unknown-key error. */
  const char *text=NULL;
  const char *column=language ? "<Russian>k__BackingField" : "<English>k__BackingField";
  for(size_t c=0;c<table->cols;++c)if(!strcmp(table->columns[c].field,column))text=table->cells[r*table->cols+c].s;
  if(!text) { result.handled=1; goto done; }
  pthread_mutex_lock(&catalog_lock); DurakGcHandle root=texts[r][language]; pthread_mutex_unlock(&catalog_lock);
  if(!root) {
    void *value=api.string_new(text); if(!value)goto done;
    DurakGcHandle candidate=api.root(value,1); if(!candidate)goto done;
    pthread_mutex_lock(&catalog_lock);
    root=texts[r][language];
    if(!root)texts[r][language]=root=candidate;
    pthread_mutex_unlock(&catalog_lock);
    if(root!=candidate)api.root_free(candidate);
  }
  result.value=api.root_get(root); result.handled=1;
done:
  errno=saved; return result;
}
