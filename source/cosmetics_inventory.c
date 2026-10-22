#include "cosmetics_inventory.h"
#include "util.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>

enum { SQL_OK=0, SQL_ERROR=1, SQL_MISUSE=21, SQL_ROW=100, SQL_DONE=101 };
typedef struct {
  int (*prepare)(void *,const char *,int,void **,const char **);
  int (*step)(void *);
  int (*finalize)(void *);
  const unsigned char *(*text)(void *,int);
  int (*integer)(void *,int);
  int (*exec)(void *,const char *,void *,void *,char **);
  int (*extended)(void *);
  const char *(*message)(void *);
  const char *(*filename)(void *,const char *);
} InventorySqlite;
typedef struct { const char *table, *column; int count; } Inventory;
static const Inventory inventories[] = {
  {"covers","dict_cover_id",8}, {"avatars","dict_avatar_id",39},
  {"gadgets","dict_gadget_id",4}
};
typedef struct { const char *p; size_t n; int quoted; } Token;
static int equal(Token t,const char *s) {
  if (t.n!=strlen(s)) return 0;
  for(size_t i=0;i<t.n;++i) if(tolower((unsigned char)t.p[i])!=tolower((unsigned char)s[i])) return 0;
  return 1;
}
static Token next_token(const char **p,const char *end) {
  while(*p<end) {
    if(isspace((unsigned char)**p)) { ++*p; continue; }
    if(end-*p>=2 && (*p)[0]=='-' && (*p)[1]=='-') {
      *p+=2; while(*p<end && **p!='\n') ++*p; continue;
    }
    if(end-*p>=2 && (*p)[0]=='/' && (*p)[1]=='*') {
      *p+=2; while(end-*p>=2 && !((*p)[0]=='*' && (*p)[1]=='/')) ++*p;
      if(end-*p<2) { *p=end; break; } *p+=2; continue;
    }
    break;
  }
  Token t={*p,0,0}; if(*p==end) return t;
  char quote=**p;
  if(quote=='"' || quote=='`' || quote=='[' || quote=='\'') {
    t.quoted=quote; t.p=++*p;
    char close=quote=='[' ? ']' : quote;
    while(*p<end && **p!=close) ++*p;
    t.n=(size_t)(*p-t.p);
    if(*p<end) ++*p;
    return t;
  }
  if(isalnum((unsigned char)**p) || **p=='_') {
    do { ++*p; } while(*p<end && (isalnum((unsigned char)**p) || **p=='_'));
  } else ++*p;
  t.n=(size_t)(*p-t.p); return t;
}
static const Inventory *selected_inventory(const char *sql,int length) {
  if(!sql || !length) return NULL;
  size_t n=length<0 ? strlen(sql) : strnlen(sql,(size_t)length);
  const char *p=sql,*end=sql+n;
  Token t=next_token(&p,end);
  if(t.quoted || !equal(t,"select")) return NULL;
  while(p<end) {
    t=next_token(&p,end);
    if(t.quoted || !equal(t,"from")) continue;
    t=next_token(&p,end);
    const char *peek=p; Token dot=next_token(&peek,end);
    if(equal(dot,".")) {
      if(!equal(t,"main")) return NULL;
      p=peek; t=next_token(&p,end);
    }
    if(t.quoted=='\'') return NULL;
    for(size_t i=0;i<sizeof(inventories)/sizeof(inventories[0]);++i)
      if(equal(t,inventories[i].table)) return &inventories[i];
    return NULL;
  }
  return NULL;
}
static int report(InventorySqlite *a,void *db,const Inventory *inventory,int rc,const char *operation) {
  int saved=errno;
  durak_log_printf("[INVENTORY ERROR] %s table=%s rc=%d extended=%d errno=%d message=%s\n",
                   operation,inventory->table,rc,a->extended(db),saved,a->message(db));
  errno=saved; return rc;
}
static int schema(InventorySqlite *a,void *db,const Inventory *i) {
  char sql[80]; snprintf(sql,sizeof(sql),"PRAGMA main.table_info(\"%s\")",i->table);
  void *stmt=NULL; int rc=a->prepare(db,sql,-1,&stmt,NULL);
  if(rc) {
    int saved=errno;
    report(a,db,i,rc,"schema prepare"); if(stmt) a->finalize(stmt);
    errno=saved; return rc;
  }
  int id=0,item=0,number=0,columns=0,valid=1;
  while((rc=a->step(stmt))==SQL_ROW) {
    const char *name=(const char *)a->text(stmt,1),*type=(const char *)a->text(stmt,2);
    ++columns;
    if(!name || !type || !equal((Token){type,strlen(type),0},"INTEGER")) { valid=0; continue; }
    if(!strcmp(name,"id") && a->integer(stmt,5)==1) ++id;
    else if(!strcmp(name,i->column) && a->integer(stmt,5)==0) ++item;
    else if(!strcmp(name,"number") && a->integer(stmt,5)==0) ++number;
    else valid=0;
  }
  int saved=errno;
  if(rc!=SQL_DONE) report(a,db,i,rc,"schema step");
  int final=a->finalize(stmt);
  if(rc!=SQL_DONE) { errno=saved; return rc; }
  if(final) return report(a,db,i,final,"schema finalize");
  int gadget=!strcmp(i->table,"gadgets");
  if(!valid || id!=1 || item!=1 || number!=gadget || columns!=2+gadget) {
    durak_log_printf("[INVENTORY ERROR] Unexpected %s schema: columns=%d id=%d item=%d number=%d; no changes\n",
                     i->table,columns,id,item,number);
    return SQL_MISUSE;
  }
  return SQL_OK;
}
int durak_inventory_before_query(void *db,const char *sql,int length,void *(*resolve)(const char *)) {
  const Inventory *i=selected_inventory(sql,length);
  if(!i || !db) return SQL_OK;
  int incoming_errno=errno;
  InventorySqlite a={0};
#define API(field,name) do { a.field=resolve(name); if(!a.field) { \
  durak_log_printf("[INVENTORY ERROR] Missing %s\n",name); return SQL_MISUSE; } } while(0)
  API(filename,"sqlite3_db_filename");
  const char *filename=a.filename(db,"main");
  if(!filename || (strcmp(filename,"/switch/durak_nx/metrics.bytes") &&
                  strcmp(filename,"sdmc:/switch/durak_nx/metrics.bytes"))) {
    errno=incoming_errno; return SQL_OK;
  }
  API(prepare,"sqlite3_prepare_v2"); API(step,"sqlite3_step");
  API(finalize,"sqlite3_finalize"); API(text,"sqlite3_column_text");
  API(integer,"sqlite3_column_int"); API(exec,"sqlite3_exec");
  API(extended,"sqlite3_extended_errcode"); API(message,"sqlite3_errmsg");
#undef API
  int rc=schema(&a,db,i);
  if(rc) return rc;
  /* No CREATE/REPLACE/DELETE: the game owns schema and existing ownership. */
  char ids[1000]; size_t used=0;
  for(int id=1;id<=i->count;++id) {
    int n=snprintf(ids+used,sizeof(ids)-used,"%sSELECT %d AS n",id==1 ? "" : " UNION ALL ",id);
    if(n<0 || (size_t)n>=sizeof(ids)-used) {
      durak_log_printf("[INVENTORY ERROR] Catalog SQL exceeds bounded buffer\n");
      return SQL_MISUSE;
    }
    used+=(size_t)n;
  }
  char statement[1800]; int gadget=!strcmp(i->table,"gadgets");
  snprintf(statement,sizeof(statement),
    "INSERT INTO \"%s\" (\"%s\"%s) SELECT src.n%s FROM (%s) AS src "
    "WHERE NOT EXISTS (SELECT 1 FROM \"%s\" WHERE \"%s\"=src.n)",
    i->table,i->column,gadget ? ",number" : "",gadget ? ",1" : "",ids,i->table,i->column);
  rc=a.exec(db,"SAVEPOINT durak_nx_inventory",NULL,NULL,NULL);
  if(rc) return report(&a,db,i,rc,"savepoint");
  rc=a.exec(db,statement,NULL,NULL,NULL);
  if(!rc && gadget)
    rc=a.exec(db,"UPDATE gadgets SET number=1 WHERE dict_gadget_id BETWEEN 1 AND 4 AND (number IS NULL OR number<1)",NULL,NULL,NULL);
  if(!rc) rc=a.exec(db,"RELEASE durak_nx_inventory",NULL,NULL,NULL);
  if(rc) {
    int saved=errno;
    report(&a,db,i,rc,"grant");
    int cleanup=a.exec(db,"ROLLBACK TO durak_nx_inventory",NULL,NULL,NULL);
    if(cleanup) report(&a,db,i,cleanup,"rollback");
    cleanup=a.exec(db,"RELEASE durak_nx_inventory",NULL,NULL,NULL);
    if(cleanup) report(&a,db,i,cleanup,"release after rollback");
    errno=saved; return rc;
  }
  static atomic_uint logged;
  unsigned bit=1u<<(unsigned)(i-inventories);
  if(!(atomic_fetch_or(&logged,bit) & bit)) {
    durak_log_printf("[INVENTORY] Granted %s catalog: %d items; existing rows retained%s\n",
                     i->table,i->count,gadget ? "; positive stock, consumption patched" : "");
  }
  errno=incoming_errno; return SQL_OK;
}
