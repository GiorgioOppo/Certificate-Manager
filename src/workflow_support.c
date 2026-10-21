#include "workflow_support.h"
#include "app.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>

static int fail(char *err,size_t n,const char *message) { snprintf(err,n,"%s",message);return 0; }
static int hex(unsigned char c) { return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1; }
static char *decode(const unsigned char *s,size_t length) {
    char *value=malloc(length+1);if(!value)return NULL;size_t p=0;
    for(size_t i=0;i<length;i++) { unsigned char c=s[i];
        if(c=='%'){if(i+2>=length||hex(s[i+1])<0||hex(s[i+2])<0){free(value);return NULL;}c=(unsigned char)(hex(s[i+1])*16+hex(s[i+2]));i+=2;}
        else if(c=='+')c=' ';
        if(!c||(c<32&&c!='\n'&&c!='\r'&&c!='\t')||c==127){free(value);return NULL;}value[p++]=(char)c;
    }value[p]=0;return value;
}
void wf_form_free(WFForm *f) { for(size_t i=0;i<f->count;i++){free(f->keys[i]);free(f->values[i]);}free(f->keys);free(f->values);memset(f,0,sizeof *f); }
int wf_form_parse(const unsigned char *body,size_t length,WFForm *f,char *err,size_t n) {
    memset(f,0,sizeof *f);if(length>4U*1024U*1024U)return fail(err,n,"Modulo troppo grande.");
    for(size_t start=0;start<length;) {
        size_t end=start;while(end<length&&body[end]!='&')end++;size_t eq=start;while(eq<end&&body[eq]!='=')eq++;
        if(eq==end||f->count>=40000)goto invalid;
        char *key=decode(body+start,eq-start),*value=decode(body+eq+1,end-eq-1);
        if(!key||!*key||!value){free(key);free(value);goto invalid;}
        char **keys=realloc(f->keys,(f->count+1)*sizeof *keys);if(!keys){free(key);free(value);goto invalid;}f->keys=keys;
        char **values=realloc(f->values,(f->count+1)*sizeof *values);if(!values){free(key);free(value);goto invalid;}f->values=values;
        f->keys[f->count]=key;f->values[f->count++]=value;start=end+1;
    }return 1;
invalid:wf_form_free(f);return fail(err,n,"Modulo non valido.");
}
size_t wf_count(const WFForm *f,const char *key) { size_t count=0;for(size_t i=0;i<f->count;i++)if(!strcmp(f->keys[i],key))count++;return count; }
const char *wf_nth(const WFForm *f,const char *key,size_t index) { for(size_t i=0;i<f->count;i++)if(!strcmp(f->keys[i],key)&&!index--)return f->values[i];return NULL; }
const char *wf_get(const WFForm *f,const char *key) { return wf_count(f,key)==1?wf_nth(f,key,0):NULL; }
int wf_number(const char *s,int64_t min,int64_t max,int64_t *out) { if(!s||!*s)return 0;for(const char *p=s;*p;p++)if(*p<'0'||*p>'9')return 0;char *end;errno=0;long long x=strtoll(s,&end,10);if(errno||*end||x<min||x>max)return 0;*out=(int64_t)x;return 1; }
int wf_json_rows(Store *s,FILE *out,const char *sql,int64_t id,char *err,size_t n) {
    sqlite3_stmt *q=NULL;if(sqlite3_prepare_v2(s->db,sql,-1,&q,NULL)!=SQLITE_OK)return fail(err,n,sqlite3_errmsg(s->db));
    if(sqlite3_bind_parameter_count(q))sqlite3_bind_int64(q,1,id);
    fputc('[',out);int first=1,rc;
    while((rc=sqlite3_step(q))==SQLITE_ROW){if(!first)fputc(',',out);first=0;fputc('{',out);
        for(int i=0;i<sqlite3_column_count(q);i++){if(i)fputc(',',out);app_json_string(out,sqlite3_column_name(q,i));fputc(':',out);int type=sqlite3_column_type(q,i);if(type==SQLITE_INTEGER)fprintf(out,"%"PRId64,(int64_t)sqlite3_column_int64(q,i));else if(type==SQLITE_NULL)fputs("null",out);else if(type==SQLITE_FLOAT)fprintf(out,"%.8g",sqlite3_column_double(q,i));else app_json_string(out,(const char *)sqlite3_column_text(q,i));}fputc('}',out);
    }fputc(']',out);sqlite3_finalize(q);return rc==SQLITE_DONE?1:fail(err,n,sqlite3_errmsg(s->db));
}
int wf_audit(Store *s,const char *entity,int64_t id,const char *action,const char *detail,char *err,size_t n) {
    sqlite3_stmt *q=NULL;int ok=sqlite3_prepare_v2(s->db,"INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES(?1,?2,?3,?4,?5)",-1,&q,NULL)==SQLITE_OK;
    if(ok){sqlite3_bind_text(q,1,entity,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(q,2,id);sqlite3_bind_text(q,3,action,-1,SQLITE_TRANSIENT);sqlite3_bind_text(q,4,detail?detail:"",-1,SQLITE_TRANSIENT);sqlite3_bind_int64(q,5,(int64_t)time(NULL));ok=sqlite3_step(q)==SQLITE_DONE;}sqlite3_finalize(q);return ok?1:fail(err,n,sqlite3_errmsg(s->db));
}
const char *wf_schema(void) {
    static char schema[16384];
    if(schema[0])return schema;
    static const char *parts[]={
    "CREATE TABLE workflow_audit(id INTEGER PRIMARY KEY,entity_type TEXT NOT NULL,entity_id INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL);",
    "CREATE INDEX workflow_audit_entity ON workflow_audit(entity_type,entity_id,id);",
    "CREATE TRIGGER audit_certificate_add AFTER INSERT ON certificates BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('certificate',NEW.id,'import',NEW.fingerprint,strftime('%s','now'));END;",
    "CREATE TRIGGER audit_certificate_archive AFTER UPDATE OF archived,superseded_by ON certificates WHEN OLD.archived<>NEW.archived OR OLD.superseded_by IS NOT NEW.superseded_by BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('certificate',NEW.id,'archive',NEW.fingerprint,strftime('%s','now'));END;",
    "CREATE TRIGGER audit_certificate_delete BEFORE DELETE ON certificates BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('certificate',OLD.id,'delete',OLD.fingerprint,strftime('%s','now'));END;",
    "CREATE TRIGGER audit_person_add AFTER INSERT ON directory_people BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('person',NEW.id,'create',NEW.email,strftime('%s','now'));END;",
    "CREATE TRIGGER audit_person_change AFTER UPDATE ON directory_people WHEN OLD.name<>NEW.name OR OLD.email<>NEW.email BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('person',NEW.id,'update',OLD.name||' <'||OLD.email||'> -> '||NEW.name||' <'||NEW.email||'>',strftime('%s','now'));END;",
    "CREATE TRIGGER audit_person_remove BEFORE DELETE ON directory_people BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('person',OLD.id,'delete',OLD.email,strftime('%s','now'));END;",
    "CREATE TRIGGER audit_group_change AFTER UPDATE ON directory_groups BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('group',NEW.id,'update',OLD.name||' -> '||NEW.name,strftime('%s','now'));END;",
    "CREATE TRIGGER audit_contact_add AFTER INSERT ON contacts BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('certificate',NEW.certificate_id,'contact_add',NEW.role||': '||NEW.email,strftime('%s','now'));END;",
    "CREATE TRIGGER audit_contact_remove AFTER DELETE ON contacts BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('certificate',OLD.certificate_id,'contact_remove',OLD.role||': '||OLD.email,strftime('%s','now'));END;",
    "CREATE TRIGGER audit_job_add AFTER INSERT ON renewal_jobs BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('renewal',NEW.id,'create',NEW.status,strftime('%s','now'));END;",
    "CREATE TRIGGER audit_job_update AFTER UPDATE ON renewal_jobs WHEN OLD.status<>NEW.status OR OLD.responsible<>NEW.responsible OR OLD.notes<>NEW.notes OR OLD.planned_install_at IS NOT NEW.planned_install_at OR OLD.planned_renewal_at IS NOT NEW.planned_renewal_at BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('renewal',NEW.id,'update',OLD.status||' -> '||NEW.status||'; '||NEW.responsible||'; '||NEW.notes,strftime('%s','now'));END;",
    "CREATE TRIGGER audit_monitor_config AFTER UPDATE ON monitors WHEN OLD.target<>NEW.target OR OLD.enabled<>NEW.enabled OR OLD.certificate_id<>NEW.certificate_id OR OLD.interval_seconds<>NEW.interval_seconds BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('monitor',NEW.id,'configuration',OLD.target||' -> '||NEW.target,strftime('%s','now'));END;",
    "CREATE TRIGGER audit_delivery AFTER UPDATE OF status ON outbox WHEN OLD.status<>NEW.status BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('certificate',NEW.certificate_id,'email_'||NEW.status,NEW.recipient_email||'; '||NEW.kind,strftime('%s','now'));END;",
    "CREATE TRIGGER audit_policy_add AFTER INSERT ON reminder_policies BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('certificate',NEW.certificate_id,'policy_create',NEW.thresholds||'; '||NEW.escalation_email,strftime('%s','now'));END;",
    "CREATE TRIGGER audit_policy_update AFTER UPDATE ON reminder_policies BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('certificate',NEW.certificate_id,'policy_update',OLD.thresholds||' -> '||NEW.thresholds||'; '||NEW.escalation_email,strftime('%s','now'));END;",
    "CREATE TRIGGER audit_group_add AFTER INSERT ON directory_groups BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('group',NEW.id,'create',NEW.name,strftime('%s','now'));END;",
    "CREATE TRIGGER audit_group_remove BEFORE DELETE ON directory_groups BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('group',OLD.id,'delete',OLD.name,strftime('%s','now'));END;",
    "CREATE TRIGGER audit_monitor_add AFTER INSERT ON monitors BEGIN INSERT INTO workflow_audit(entity_type,entity_id,action,detail,created_at) VALUES('monitor',NEW.id,'create',NEW.target,strftime('%s','now'));END;"
    };
    size_t used=0;for(size_t i=0;i<sizeof parts/sizeof parts[0];i++){size_t length=strlen(parts[i]);if(used+length>=sizeof schema)return "";memcpy(schema+used,parts[i],length);used+=length;}schema[used]=0;return schema;
}
