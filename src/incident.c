#define _POSIX_C_SOURCE 200809L
#include "incident.h"
#include "app.h"
#include "delivery.h"
#include "workflow_support.h"
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

const char *incident_schema(void) {
    return "CREATE TABLE monitor_options("
        "monitor_id INTEGER PRIMARY KEY REFERENCES monitors(id) ON DELETE CASCADE,"
        "failure_threshold INTEGER NOT NULL DEFAULT 1 CHECK(failure_threshold BETWEEN 1 AND 10),"
        "consecutive_failures INTEGER NOT NULL DEFAULT 0,"
        "incident_open INTEGER NOT NULL DEFAULT 0 CHECK(incident_open IN(0,1)),"
        "raw_event_id INTEGER REFERENCES monitor_events(id) ON DELETE SET NULL,"
        "last_alert_event_id INTEGER REFERENCES monitor_events(id) ON DELETE SET NULL,"
        "maintenance_start INTEGER NOT NULL DEFAULT 0,maintenance_end INTEGER NOT NULL DEFAULT 0,"
        "maintenance_reason TEXT NOT NULL DEFAULT '',maintenance_processed INTEGER NOT NULL DEFAULT 1,"
        "post_maintenance_check INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE event_claims(event_id INTEGER PRIMARY KEY REFERENCES monitor_events(id) ON DELETE CASCADE,"
        "responsible TEXT NOT NULL DEFAULT '',notes TEXT NOT NULL DEFAULT '',due_at INTEGER,"
        "status TEXT NOT NULL DEFAULT 'open' CHECK(status IN('open','investigating','resolved')),"
        "created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);"
        "INSERT INTO monitor_options(monitor_id,consecutive_failures,incident_open,raw_event_id,last_alert_event_id) "
        "SELECT m.id,CASE WHEN m.last_status='unreachable' THEN 1 ELSE 0 END,"
        "CASE WHEN m.last_status IN('pending','ok') THEN 0 ELSE 1 END,"
        "(SELECT e.id FROM monitor_events e WHERE e.monitor_id=m.id AND e.kind<>'recovered' ORDER BY e.id DESC LIMIT 1),"
        "(SELECT e.id FROM monitor_events e JOIN outbox o ON o.event_id=e.id WHERE e.monitor_id=m.id AND e.kind<>'recovered' ORDER BY e.id DESC LIMIT 1) "
        "FROM monitors m;";
}
static int failure(Store *s,char *err,size_t n) { if(err&&n)snprintf(err,n,"%s",sqlite3_errmsg(s->db));return 0; }
static void rollback(Store *s,const char *name,int outer){
    if(outer)sqlite3_exec(s->db,"ROLLBACK",NULL,NULL,NULL);
    else{char sql[160];snprintf(sql,sizeof sql,"ROLLBACK TO %s; RELEASE %s",name,name);sqlite3_exec(s->db,sql,NULL,NULL,NULL);}
}
static int bind_text(sqlite3_stmt *q,int i,const char *v){return sqlite3_bind_text(q,i,v?v:"",-1,SQLITE_TRANSIENT)==SQLITE_OK;}
static int equal_fingerprint(const char *a,const char *b){
    for(;;){while(*a==':')a++;while(*b==':')b++;unsigned char x=(unsigned char)*a,y=(unsigned char)*b;if(toupper(x)!=toupper(y))return 0;if(!x)return 1;a++;b++;}
}
static int insert_event(Store *s,int64_t monitor_id,int64_t now,const char *kind,const char *message,const char *expected,const char *observed,int64_t *id,char *err,size_t n){
    sqlite3_stmt *q=NULL;int ok=sqlite3_prepare_v2(s->db,"INSERT INTO monitor_events(monitor_id,kind,message,expected_fingerprint,observed_fingerprint,created_at) VALUES(?1,?2,?3,?4,?5,?6)",-1,&q,NULL)==SQLITE_OK&&sqlite3_bind_int64(q,1,monitor_id)==SQLITE_OK&&bind_text(q,2,kind)&&bind_text(q,3,message)&&bind_text(q,4,expected)&&bind_text(q,5,observed)&&sqlite3_bind_int64(q,6,now)==SQLITE_OK&&sqlite3_step(q)==SQLITE_DONE;
    if(ok)*id=sqlite3_last_insert_rowid(s->db);else failure(s,err,n);
    sqlite3_finalize(q);
    return ok && wf_audit(s,"monitor_event",*id,"observation",message,err,n);
}
static int record_inner(Store *s,int64_t monitor_id,int64_t now,const char *status,const char *previous_status,const char *expected,const char *observed,const char *previous_fingerprint,const char *message,char *err,size_t n){
    sqlite3_stmt *q=NULL;int ok=sqlite3_prepare_v2(s->db,"INSERT OR IGNORE INTO monitor_options(monitor_id) VALUES(?)",-1,&q,NULL)==SQLITE_OK&&sqlite3_bind_int64(q,1,monitor_id)==SQLITE_OK&&sqlite3_step(q)==SQLITE_DONE;
    sqlite3_finalize(q);q=NULL;if(!ok)return failure(s,err,n);
    ok=sqlite3_prepare_v2(s->db,"SELECT failure_threshold,consecutive_failures,incident_open,coalesce(raw_event_id,0),coalesce(last_alert_event_id,0),maintenance_start,maintenance_end,post_maintenance_check FROM monitor_options WHERE monitor_id=?",-1,&q,NULL)==SQLITE_OK&&sqlite3_bind_int64(q,1,monitor_id)==SQLITE_OK&&sqlite3_step(q)==SQLITE_ROW;
    if(!ok){sqlite3_finalize(q);return failure(s,err,n);}
    int threshold=sqlite3_column_int(q,0),failures=sqlite3_column_int(q,1),open=sqlite3_column_int(q,2);
    int64_t raw=sqlite3_column_int64(q,3),alert=sqlite3_column_int64(q,4),start=sqlite3_column_int64(q,5),end=sqlite3_column_int64(q,6);
    int maintenance=start<=now&&end>now;
    int after_maintenance=sqlite3_column_int(q,7);
    sqlite3_finalize(q);q=NULL;
    int64_t queued_event=0;
    if(!strcmp(status,"ok")){
        failures=0;
        if(open){
            if(!insert_event(s,monitor_id,now,"recovered",message,expected,observed,&queued_event,err,n))return 0;
            if(!alert||maintenance)queued_event=0;
        }
        open=0;raw=0;alert=0;
    }else{
        if(!strcmp(status,"unreachable")){if(failures<10)failures++;}else failures=0;
        if(!raw||after_maintenance||strcmp(status,previous_status)||(observed[0]&&!equal_fingerprint(observed,previous_fingerprint))){
            if(!insert_event(s,monitor_id,now,status,message,expected,observed,&raw,err,n))return 0;
        }
        int confirmed=strcmp(status,"unreachable")||failures>=threshold;
        if(confirmed){
            open=1;
            if(!maintenance&&raw!=alert){queued_event=raw;alert=raw;}
        }
    }
    /* Each confirmed transition is a legitimate queued notification. Keep
       earlier pending anomaly and recovery messages while SMTP is paused. */
    if(queued_event){int queued=0;if(!delivery_queue_monitor_event(s,queued_event,now,&queued,err,n))return 0;}
    ok=sqlite3_prepare_v2(s->db,"UPDATE monitor_options SET consecutive_failures=?1,incident_open=?2,raw_event_id=nullif(?3,0),last_alert_event_id=nullif(?4,0),post_maintenance_check=0,updated_at=?5 WHERE monitor_id=?6",-1,&q,NULL)==SQLITE_OK&&sqlite3_bind_int(q,1,failures)==SQLITE_OK&&sqlite3_bind_int(q,2,open)==SQLITE_OK&&sqlite3_bind_int64(q,3,raw)==SQLITE_OK&&sqlite3_bind_int64(q,4,alert)==SQLITE_OK&&sqlite3_bind_int64(q,5,now)==SQLITE_OK&&sqlite3_bind_int64(q,6,monitor_id)==SQLITE_OK&&sqlite3_step(q)==SQLITE_DONE;
    if(!ok)failure(s,err,n);sqlite3_finalize(q);return ok;
}
int incident_record(Store *s,int64_t monitor_id,int64_t now,const char *status,const char *previous_status,const char *expected,const char *observed,const char *previous_fingerprint,const char *message,char *err,size_t n){
    int outer=sqlite3_get_autocommit(s->db);
    if(!store_exec(s,"SAVEPOINT incident_record",err,n))return 0;
    int ok=record_inner(s,monitor_id,now,status,previous_status,expected,observed,previous_fingerprint,message,err,n);
    if(ok)ok=store_exec(s,"RELEASE incident_record",err,n);
    if(!ok)rollback(s,"incident_record",outer);return ok;
}
int incident_tick(Store *s,int64_t now,char *err,size_t n){
    /* Polling without due maintenance is read-only. In particular monitor_tick
     * calls us with busy_timeout=0 and must never retain a failed commit lock. */
    sqlite3_stmt *due=NULL;
    if(sqlite3_prepare_v2(s->db,"SELECT 1 FROM monitor_options WHERE maintenance_end>0 AND maintenance_end<=?1 AND maintenance_processed=0 LIMIT 1",-1,&due,NULL)!=SQLITE_OK)return failure(s,err,n);
    sqlite3_bind_int64(due,1,now);int rc=sqlite3_step(due);sqlite3_finalize(due);
    if(rc==SQLITE_DONE)return 1;if(rc!=SQLITE_ROW)return failure(s,err,n);
    int outer=sqlite3_get_autocommit(s->db);
    if(!store_exec(s,"SAVEPOINT incident_expiry",err,n))return 0;
    sqlite3_stmt *q=NULL;int ok=sqlite3_prepare_v2(s->db,"UPDATE monitors SET revision=revision+1,claim_until=0,next_check_at=?1,updated_at=?1 WHERE id IN(SELECT monitor_id FROM monitor_options WHERE maintenance_end>0 AND maintenance_end<=?1 AND maintenance_processed=0)",-1,&q,NULL)==SQLITE_OK&&sqlite3_bind_int64(q,1,now)==SQLITE_OK&&sqlite3_step(q)==SQLITE_DONE;
    if(!ok)failure(s,err,n);sqlite3_finalize(q);q=NULL;
    if(ok)ok=sqlite3_prepare_v2(s->db,"UPDATE monitor_options SET maintenance_processed=1,post_maintenance_check=1,updated_at=?1 WHERE maintenance_end>0 AND maintenance_end<=?1 AND maintenance_processed=0",-1,&q,NULL)==SQLITE_OK&&sqlite3_bind_int64(q,1,now)==SQLITE_OK&&sqlite3_step(q)==SQLITE_DONE;
    if(!ok)failure(s,err,n);sqlite3_finalize(q);
    if(ok)ok=store_exec(s,"RELEASE incident_expiry",err,n);
    if(!ok)rollback(s,"incident_expiry",outer);
    return ok;
}
/* A strict form decoder: duplicate fields and control characters are rejected. */
static int hex(unsigned char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static char *decode(const unsigned char *p,size_t size,int multiline){char *v=malloc(size+1);if(!v)return NULL;size_t at=0;for(size_t i=0;i<size;i++){unsigned char c=p[i];if(c=='%'){if(i+2>=size||hex(p[i+1])<0||hex(p[i+2])<0){free(v);return NULL;}c=(unsigned char)(hex(p[i+1])*16+hex(p[i+2]));i+=2;}else if(c=='+')c=' ';if((c<32&&!(multiline&&(c=='\n'||c=='\r'||c=='\t')))||c==127){free(v);return NULL;}v[at++]=(char)c;}v[at]=0;return v;}
static int field(const unsigned char *body,size_t size,const char *key,char **value){*value=NULL;for(size_t start=0;start<size;){size_t end=start,equal=start;while(end<size&&body[end]!='&')end++;while(equal<end&&body[equal]!='=')equal++;if(equal==end)goto invalid;if(equal-start==strlen(key)&&!memcmp(body+start,key,equal-start)){if(*value)goto invalid;*value=decode(body+equal+1,end-equal-1,!strcmp(key,"notes"));if(!*value)goto invalid;}start=end+1;}return 1;invalid:free(*value);*value=NULL;return 0;}
static int number(const char *v,int64_t minimum,int64_t maximum,int64_t *out){if(!v||!*v)return 0;int64_t x=0;for(const unsigned char *p=(const unsigned char*)v;*p;p++){if(*p<'0'||*p>'9'||x>(maximum-(*p-'0'))/10)return 0;x=x*10+*p-'0';}if(x<minimum||x>maximum)return 0;*out=x;return 1;}
static int emit_rows(Store *s,FILE *out,const char *sql,int64_t id,char *err,size_t n){
    sqlite3_stmt *q=NULL;int ok=sqlite3_prepare_v2(s->db,sql,-1,&q,NULL)==SQLITE_OK;if(ok&&sqlite3_bind_parameter_count(q))ok=sqlite3_bind_int64(q,1,id)==SQLITE_OK;if(!ok){sqlite3_finalize(q);return failure(s,err,n);}fputc('[',out);int first=1,rc;while((rc=sqlite3_step(q))==SQLITE_ROW){if(!first)fputc(',',out);first=0;fputc('{',out);for(int i=0;i<sqlite3_column_count(q);i++){if(i)fputc(',',out);app_json_string(out,sqlite3_column_name(q,i));fputc(':',out);if(sqlite3_column_type(q,i)==SQLITE_NULL)fputs("null",out);else if(sqlite3_column_type(q,i)==SQLITE_INTEGER)fprintf(out,"%"PRId64,(int64_t)sqlite3_column_int64(q,i));else app_json_string(out,(const char*)sqlite3_column_text(q,i));}fputc('}',out);}fputc(']',out);sqlite3_finalize(q);return rc==SQLITE_DONE?1:failure(s,err,n);
}
static int save_options(Store *s,const unsigned char *body,size_t size,int64_t now,char *err,size_t n){
    int outer=sqlite3_get_autocommit(s->db);
    const char *keys[]={"monitor_id","failure_threshold","maintenance_start","maintenance_end","maintenance_reason"};char *v[5]={0};int ok=1;int64_t id=0,threshold=1,start=0,end=0;for(size_t i=0;i<5&&ok;i++)ok=field(body,size,keys[i],&v[i]);
    if(ok)ok=number(v[0],1,INT64_MAX,&id)&&number(v[1],1,10,&threshold)&&(!v[2]||!*v[2]||number(v[2],0,INT64_MAX-86400,&start))&&(!v[3]||!*v[3]||number(v[3],0,INT64_MAX-86400,&end))&&((!start&&!end)||(end>start&&end>now))&&(!v[4]||strlen(v[4])<=1000);
    if(!ok){snprintf(err,n,"Soglia, finestra di manutenzione o motivo non validi.");goto done;}
    if(!store_exec(s,"SAVEPOINT incident_options",err,n)){ok=0;goto done;}
    sqlite3_stmt *q=NULL;ok=sqlite3_prepare_v2(s->db,"INSERT INTO monitor_options(monitor_id,failure_threshold,maintenance_start,maintenance_end,maintenance_reason,maintenance_processed,post_maintenance_check,updated_at) VALUES(?1,?2,?3,?4,?5,?6,0,?7) ON CONFLICT(monitor_id) DO UPDATE SET failure_threshold=excluded.failure_threshold,maintenance_start=excluded.maintenance_start,maintenance_end=excluded.maintenance_end,maintenance_reason=excluded.maintenance_reason,maintenance_processed=excluded.maintenance_processed,post_maintenance_check=CASE WHEN monitor_options.post_maintenance_check=1 OR (monitor_options.maintenance_start<=?7 AND monitor_options.maintenance_end>?7 AND excluded.maintenance_end=0) THEN 1 ELSE 0 END,updated_at=excluded.updated_at",-1,&q,NULL)==SQLITE_OK&&sqlite3_bind_int64(q,1,id)==SQLITE_OK&&sqlite3_bind_int64(q,2,threshold)==SQLITE_OK&&sqlite3_bind_int64(q,3,start)==SQLITE_OK&&sqlite3_bind_int64(q,4,end)==SQLITE_OK&&bind_text(q,5,v[4])&&sqlite3_bind_int(q,6,end>now?0:1)==SQLITE_OK&&sqlite3_bind_int64(q,7,now)==SQLITE_OK&&sqlite3_step(q)==SQLITE_DONE;
    if(!ok)failure(s,err,n);sqlite3_finalize(q);q=NULL;
    /* Invalidate a probe that started under a different maintenance policy. */
    if(ok)ok=sqlite3_prepare_v2(s->db,"UPDATE monitors SET revision=revision+1,claim_until=0,next_check_at=?1 WHERE id=?2",-1,&q,NULL)==SQLITE_OK&&sqlite3_bind_int64(q,1,now)==SQLITE_OK&&sqlite3_bind_int64(q,2,id)==SQLITE_OK&&sqlite3_step(q)==SQLITE_DONE;
    if(!ok)failure(s,err,n);sqlite3_finalize(q);
    char audit_detail[1400];
    snprintf(audit_detail,sizeof audit_detail,"threshold=%lld; maintenance_start=%lld; maintenance_end=%lld; reason=%s",(long long)threshold,(long long)start,(long long)end,v[4]?v[4]:"");
    if(ok)ok=wf_audit(s,"monitor",id,"monitor_options",audit_detail,err,n);
    if(ok)ok=store_exec(s,"RELEASE incident_options",err,n);if(!ok)rollback(s,"incident_options",outer);
    done:for(size_t i=0;i<5;i++)free(v[i]);return ok;
}
static int save_claim(Store *s,int64_t id,const unsigned char *body,size_t size,int64_t now,char *err,size_t n){
    int outer=sqlite3_get_autocommit(s->db);
    const char *keys[]={"responsible","notes","due_at","status"};char *v[4]={0};int ok=1;int64_t due=0;for(size_t i=0;i<4&&ok;i++)ok=field(body,size,keys[i],&v[i]);
    if(ok)ok=v[0]&&*v[0]&&strlen(v[0])<=120&&(!v[1]||strlen(v[1])<=4000)&&(!v[2]||!*v[2]||number(v[2],0,INT64_MAX-86400,&due))&&v[3]&&(!strcmp(v[3],"open")||!strcmp(v[3],"investigating")||!strcmp(v[3],"resolved"));
    if(!ok){snprintf(err,n,"Indica responsabile, stato e termine di intervento validi.");goto done;}
    if(!store_exec(s,"SAVEPOINT incident_claim",err,n)){ok=0;goto done;}
    sqlite3_stmt *q=NULL;ok=sqlite3_prepare_v2(s->db,"INSERT INTO event_claims(event_id,responsible,notes,due_at,status,created_at,updated_at) VALUES(?1,?2,?3,nullif(?4,0),?5,?6,?6) ON CONFLICT(event_id) DO UPDATE SET responsible=excluded.responsible,notes=excluded.notes,due_at=excluded.due_at,status=excluded.status,updated_at=excluded.updated_at",-1,&q,NULL)==SQLITE_OK&&sqlite3_bind_int64(q,1,id)==SQLITE_OK&&bind_text(q,2,v[0])&&bind_text(q,3,v[1])&&sqlite3_bind_int64(q,4,due)==SQLITE_OK&&bind_text(q,5,v[3])&&sqlite3_bind_int64(q,6,now)==SQLITE_OK&&sqlite3_step(q)==SQLITE_DONE;
    if(!ok)failure(s,err,n);sqlite3_finalize(q);
    char audit_detail[4500];
    snprintf(audit_detail,sizeof audit_detail,"status=%s; responsible=%s; due_at=%lld; notes=%s",v[3],v[0],(long long)due,v[1]?v[1]:"");
    if(ok)ok=wf_audit(s,"monitor_event",id,"claim",audit_detail,err,n);
    if(ok)ok=store_exec(s,"RELEASE incident_claim",err,n);
    if(!ok)rollback(s,"incident_claim",outer);
    done:for(size_t i=0;i<4;i++)free(v[i]);return ok;
}
char *incident_api(Store *s,const char *method,const char *path,const unsigned char *body,size_t bodylen,size_t *length,int *status,char *err,size_t n){
    char *result=NULL;FILE *out=NULL;int ok=0;*status=400;*length=0;if(bodylen>65536){snprintf(err,n,"Richiesta troppo grande.");return NULL;}
    if(!strcmp(method,"GET")&&!strcmp(path,"/api/incidents/state")){
        out=open_memstream(&result,length);if(!out)goto memory;
        fputs("{\"monitor_options\":",out);ok=emit_rows(s,out,"SELECT m.id AS monitor_id,coalesce(o.failure_threshold,1) AS failure_threshold,coalesce(o.consecutive_failures,0) AS consecutive_failures,coalesce(o.incident_open,0) AS incident_open,coalesce(o.maintenance_start,0) AS maintenance_start,coalesce(o.maintenance_end,0) AS maintenance_end,coalesce(o.maintenance_reason,'') AS maintenance_reason,coalesce(o.post_maintenance_check,0) AS post_maintenance_check FROM monitors m LEFT JOIN monitor_options o ON o.monitor_id=m.id ORDER BY m.id",0,err,n);
        fputs(",\"claims\":",out);if(ok)ok=emit_rows(s,out,"SELECT * FROM event_claims ORDER BY updated_at DESC,event_id DESC",0,err,n);fputc('}',out);
    }else if(!strcmp(method,"POST")&&!strcmp(path,"/api/incidents/monitor-options")){
        ok=save_options(s,body,bodylen,(int64_t)time(NULL),err,n);if(ok){result=strdup("{\"ok\":true}");if(!result)goto memory;*length=strlen(result);}
    }else{
        const char *prefix="/api/incidents/events/";size_t prefixlen=strlen(prefix);if(strncmp(path,prefix,prefixlen)){*status=404;snprintf(err,n,"Operazione non trovata.");return NULL;}
        const char *p=path+prefixlen,*end=p;while(*end>='0'&&*end<='9')end++;size_t idlen=(size_t)(end-p);char idtext[32];int64_t id=0;if(!idlen||idlen>=sizeof idtext){snprintf(err,n,"Evento non valido.");return NULL;}memcpy(idtext,p,idlen);idtext[idlen]=0;if(!number(idtext,1,INT64_MAX,&id)){snprintf(err,n,"Evento non valido.");return NULL;}
        if(!strcmp(method,"POST")&&!strcmp(end,"/claim")){
            ok=save_claim(s,id,body,bodylen,(int64_t)time(NULL),err,n);if(ok){result=strdup("{\"ok\":true}");if(!result)goto memory;*length=strlen(result);}
        }else if(!strcmp(method,"GET")&&!*end){
            out=open_memstream(&result,length);if(!out)goto memory;fputs("{\"events\":",out);ok=emit_rows(s,out,"SELECT e.*,m.target,m.last_status,m.last_checked_at,c.responsible,c.notes,c.due_at,c.status AS claim_status,c.updated_at AS claim_updated_at FROM monitor_events e JOIN monitors m ON m.id=e.monitor_id LEFT JOIN event_claims c ON c.event_id=e.id WHERE e.id=?",id,err,n);fputc('}',out);
        }else{*status=404;snprintf(err,n,"Operazione non trovata.");return NULL;}
    }
    if(out){if(ferror(out))ok=0;if(fclose(out))ok=0;}if(!ok){free(result);return NULL;}*status=200;return result;
    memory:snprintf(err,n,"Memoria insufficiente.");free(result);return NULL;
}
