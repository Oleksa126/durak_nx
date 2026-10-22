/* Exercise every original row/column, roots, both languages and progress fallback. */
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../source/static_catalog.c"

typedef struct Class Class;
typedef struct { int kind; Class *cls; } Type;
typedef struct { const char *name; Type type; int slot; } Field;
struct Class { const char *ns,*name; Class *element; Field fields[16]; size_t count; };
typedef struct { Class *cls; union { void *p; int32_t i; float f; } values[16]; } Object;
typedef struct { char *text; int length; uint16_t chars[256]; } String;
static void *roots[20000]; static unsigned next_root=1,live_roots,new_calls,strings,barriers;
static int fail_new;
static void *managed[30000];static size_t managed_count;
static void remember(void *o){assert(o && managed_count<30000);managed[managed_count++]=o;}
static int is_managed(void *o){for(size_t i=0;i<managed_count;++i)if(managed[i]==o)return 1;return 0;}
void durak_log_printf(const char *fmt,...) { (void)fmt; }
static void *method_type(const void *m) { return (void *)m; }
static void *from_type(const void *t) { return ((Type *)t)->cls; }
static void *object_class(void *o) {return ((Object *)o)->cls;}
static void *element(void *c) {return ((Class *)c)->element;}
static void *parent(void *c) {(void)c;return NULL;}
static const char *class_name(void *c){return ((Class *)c)->name;}
static const char *class_ns(void *c){return ((Class *)c)->ns;}
static void *find_field(void *c,const char *name) {
  Class *cls=c; for(size_t i=0;i<cls->count;++i)if(!strcmp(cls->fields[i].name,name))return &cls->fields[i]; return NULL;
}
static const void *field_type(void *f){return &((Field *)f)->type;}
static int kind(const void *t){return ((Type *)t)->kind;}
static void get(void *o,void *f,void *v){Field *field=f;memcpy(v,&((Object *)o)->values[field->slot],field->type.kind==8 || field->type.kind==12 ? 4 : sizeof(void *));}
static void set(void *o,void *f,void *v) {
  Field *field=f;
  if(field->type.kind==8 || field->type.kind==12)memcpy(&((Object *)o)->values[field->slot],v,4);
  else {assert(!v || is_managed(v));((Object *)o)->values[field->slot].p=v;}
}
static void *object_new(void *c){++new_calls;if(fail_new){--fail_new;return NULL;}Object *o=calloc(1,sizeof(*o));assert(o);o->cls=c;remember(o);return o;}
static void *array_new(void *c,uintptr_t n){(void)c;void *o=calloc(1,32+n*sizeof(void *));remember(o);return o;}
static uint32_t array_header(void){return 32;}
static void barrier(void *o,void **slot,void *v){(void)o;*slot=v;++barriers;}
/* Deliberately return opaque handles above 4 GiB. Any truncated return value,
 * cache entry, local or argument fails before pretending to preserve a root. */
#define ROOT_HIGH ((uintptr_t)0xd00000000ULL)
static DurakGcHandle root(void *o,int pinned){assert(o && pinned && next_root<20000);roots[next_root]=o;++live_roots;return ROOT_HIGH | next_root++;}
static unsigned root_index(DurakGcHandle h){assert((h & ~(uintptr_t)0xffffffffULL)==ROOT_HIGH);unsigned i=(unsigned)(h & 0xffffffffULL);assert(i && i<next_root && roots[i]);return i;}
static void *root_get(DurakGcHandle h){return roots[root_index(h)];}
static void root_free(DurakGcHandle h){roots[root_index(h)]=NULL;--live_roots;}
static void *string_new(const char *s){String *str=calloc(1,sizeof(*str));assert(str);str->text=strdup(s);str->length=(int)strlen(s);for(int i=0;i<str->length && i<256;++i)str->chars[i]=(unsigned char)s[i];++strings;remember(str);return str;}
static int32_t string_length(void *s){return ((String *)s)->length;}
static const uint16_t *string_chars(void *s){return ((String *)s)->chars;}
static void check_row(Object *row,const DurakStaticTable *table,size_t r) {
  for(size_t c=0;c<table->cols;++c) {
    const DurakStaticCell *v=&table->cells[r*table->cols+c];
    if(table->columns[c].kind==8)assert(row->values[c].i==v->i);
    else if(table->columns[c].kind==12)assert(row->values[c].f==v->f);
    else if(!v->s)assert(!row->values[c].p);
    else assert(!strcmp(((String *)row->values[c].p)->text,v->s));
  }
}
int main(void) {
  DurakStaticApi bindings={method_type,from_type,object_class,element,parent,class_name,class_ns,find_field,field_type,kind,get,set,object_new,array_new,array_header,barrier,root,root_get,root_free,string_new,string_length,string_chars};
  durak_static_bind(&bindings);
  static Class rows[DURAK_STATIC_TABLE_COUNT],arrays[DURAK_STATIC_TABLE_COUNT],list_classes[DURAK_STATIC_TABLE_COUNT];
  int manager=1;
  size_t total=0;
  for(size_t t=0;t<DURAK_STATIC_TABLE_COUNT;++t) {
    const DurakStaticTable *table=&catalog_tables[t]; Class *row=&rows[t],*arr=&arrays[t],*list=&list_classes[t];
    row->ns=table->ns;row->name=table->name;row->count=table->cols;
    for(size_t c=0;c<table->cols;++c)row->fields[c]=(Field){table->columns[c].field,{table->columns[c].kind,NULL},(int)c};
    arr->element=row;
    list->ns="System.Collections.Generic";list->name="List`1";list->count=3;
    list->fields[0]=(Field){"_items",{29,arr},0};list->fields[1]=(Field){"_size",{8,NULL},1};
    list->fields[2]=(Field){"_version",{8,NULL},2};
    Type method={18,list},row_method={18,row};
    if(t==0) { fail_new=1;unsigned before=live_roots;assert(!durak_static_table(&manager,&method).handled);assert(live_roots==before); }
    errno=EIO;DurakStaticResult result=durak_static_table(&manager,&method);assert(errno==EIO && result.handled && result.value);
    Object *obj=result.value; assert(obj->values[1].i==(int32_t)table->rows);
    void **entries=(void **)((char *)obj->values[0].p+32);
    for(size_t r=0;r<table->rows;++r) {
      check_row(entries[r],table,r);
      DurakStaticResult one=durak_static_row(&manager,table->cells[r*table->cols].i,&row_method);
      assert(one.handled && one.value);check_row(one.value,table,r);
    }
    obj->values[1].i=0; /* A consumer may clear/sort/edit its own result. */
    ((Object *)entries[0])->values[0].i=-999;
    DurakStaticResult again=durak_static_table(&manager,&method);
    assert(again.handled && again.value!=obj);
    Object *fresh=again.value;assert(fresh->values[1].i==(int32_t)table->rows && fresh->values[2].i==(int32_t)table->rows);
    void **fresh_entries=(void **)((char *)fresh->values[0].p+32);
    for(size_t r=0;r<table->rows;++r)check_row(fresh_entries[r],table,r);
    assert(!durak_static_row(&manager,-12345,&row_method).handled);
    total+=table->rows;
  }
  assert(barriers==total*2 && live_roots==0);
  Class metrics={.ns="MetricsTypes",.name="single_stats"};Type progress_method={18,&metrics};
  assert(!durak_static_row(&manager,1,&progress_method).handled);
  assert(!durak_static_table(&manager,&progress_method).handled);
  assert(!durak_static_row(NULL,1,&progress_method).handled);
  Class locale={.ns="",.name="LocalizationManager",.count=1};locale.fields[0]=(Field){"loclang",{8,NULL},0};
  Object localizer={.cls=&locale};
  const DurakStaticTable *generic=&catalog_tables[2];assert(!strcmp(generic->name,"Generic"));
  unsigned nonnull=0;
  for(size_t r=0;r<generic->rows;++r) {
    void *key=string_new(generic->cells[r*generic->cols+1].s);
    for(int language=0;language<2;++language) {
      localizer.values[0].i=language ? 30 : 10;
      errno=EDOM;DurakStaticResult text=durak_static_text(&localizer,key,NULL);assert(text.handled && errno==EDOM);
      const char *expected=generic->cells[r*generic->cols+2+language].s;
      if(expected){assert(!strcmp(((String *)text.value)->text,expected));++nonnull;}else assert(!text.value);
      unsigned before=strings;assert(durak_static_text(&localizer,key,NULL).value==text.value && strings==before);
    }
  }
  assert(live_roots==nonnull);
  assert(!durak_static_text(&localizer,string_new("unknown_key_for_test"),NULL).handled);
  localizer.values[0].i=99;
  assert(!durak_static_text(&localizer,string_new("single_game"),NULL).handled);
  assert(!durak_static_text(&localizer,NULL,NULL).handled);
  puts("compiled catalogs: every row/column, GC roots, 2 languages, errno and original progress/error fallback passed");
  return 0;
}
