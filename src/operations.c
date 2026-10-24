#define _POSIX_C_SOURCE 200809L
#include "operations.h"
#include "workflow_support.h"
#include "workspace.h"
#include "lifecycle.h"
#include "chain.h"
#include "app.h"
#include <ctype.h>
#include <inttypes.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static int fail(char *err,size_t n,const char *msg) {snprintf(err,n,"%s",msg);return 0;}
static int dbfail(Store *s,char *err,size_t n) {return fail(err,n,sqlite3_errmsg(s->db));}
static int prep(Store *s,sqlite3_stmt **q,const char *sql,char *err,size_t n) {return sqlite3_prepare_v2(s->db,sql,-1,q,NULL)==SQLITE_OK||dbfail(s,err,n);}
static void text(sqlite3_stmt *q,int i,const char *value) {sqlite3_bind_text(q,i,value?value:"",-1,SQLITE_TRANSIENT);}
static int done(Store *s,sqlite3_stmt **q,char *err,size_t n) {int ok=sqlite3_step(*q)==SQLITE_DONE;if(!ok)dbfail(s,err,n);sqlite3_finalize(*q);*q=NULL;return ok;}
static int finish(Store *s,int ok,char *err,size_t n) {if(ok)ok=store_exec(s,"RELEASE operations",err,n);if(!ok)sqlite3_exec(s->db,"ROLLBACK TO operations; RELEASE operations",NULL,NULL,NULL);return ok;}
static int object(Store *s,FILE *out,const char *sql,int64_t id,char *err,size_t n) {
    sqlite3_stmt *q=NULL;if(!prep(s,&q,sql,err,n))return 0;sqlite3_bind_int64(q,1,id);int rc=sqlite3_step(q);
    if(rc!=SQLITE_ROW){sqlite3_finalize(q);return fail(err,n,"Elemento non trovato.");}
    fputc('{',out);for(int i=0;i<sqlite3_column_count(q);i++){if(i)fputc(',',out);app_json_string(out,sqlite3_column_name(q,i));fputc(':',out);int type=sqlite3_column_type(q,i);if(type==SQLITE_INTEGER)fprintf(out,"%"PRId64,(int64_t)sqlite3_column_int64(q,i));else if(type==SQLITE_NULL)fputs("null",out);else app_json_string(out,(const char*)sqlite3_column_text(q,i));}fputc('}',out);sqlite3_finalize(q);return 1;
}
static const char *policy_before_sql="SELECT coalesce(p.thresholds,'45,30,15,2,0') AS thresholds,coalesce(p.enabled,1) AS enabled,coalesce(p.escalation_email,'') AS escalation_email,coalesce(p.escalation_name,'') AS escalation_name,coalesce(p.escalation_after_days,7) AS escalation_after_days FROM certificates c LEFT JOIN reminder_policies p ON p.certificate_id=c.id WHERE c.id=?1";
static const char *certificate_sql="SELECT id,common_name,sans,issuer,subject,not_before,not_after,fingerprint,serial,key_algorithm,key_bits,signature_algorithm,is_ca,archived FROM certificates WHERE id=?1";
const char *operations_schema(void) {return
    "CREATE TABLE policy_templates(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL UNIQUE COLLATE NOCASE,thresholds TEXT NOT NULL,enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),escalation_email TEXT NOT NULL DEFAULT '',escalation_name TEXT NOT NULL DEFAULT '',escalation_after_days INTEGER NOT NULL DEFAULT 7 CHECK(escalation_after_days BETWEEN 0 AND 365),updated_at INTEGER NOT NULL);"
    "CREATE TABLE renewal_closure_reports(job_id INTEGER PRIMARY KEY REFERENCES renewal_jobs(id) ON DELETE CASCADE,mode TEXT NOT NULL CHECK(mode IN('verified','retired')),captured_at INTEGER NOT NULL,report_json TEXT NOT NULL);";
}

typedef struct {char thresholds[256],email[255],name[121];int enabled,days,values[64],count;} Policy;
static int plain(const char *value,size_t max) {if(!value||strlen(value)>max)return 0;for(const unsigned char*p=(const unsigned char*)value;*p;p++)if(*p<32||*p==127)return 0;return 1;}
static int parse_policy(const WFForm *f,Policy *p,char *err,size_t n) {
    memset(p,0,sizeof *p);const char *thresholds=wf_get(f,"thresholds"),*email=wf_get(f,"escalation_email"),*name=wf_get(f,"escalation_name");int64_t enabled,days;
    if(!thresholds||strlen(thresholds)>200||!email||!plain(name,120)||(*email&&!store_email_valid(email))||!wf_number(wf_get(f,"enabled"),0,1,&enabled)||!wf_number(wf_get(f,"escalation_after_days"),0,365,&days))return fail(err,n,"Regola promemoria non valida.");
    char compact[256];size_t length=0;for(const unsigned char*q=(const unsigned char*)thresholds;*q;q++)if(!isspace(*q))compact[length++]=(char)*q;compact[length]=0;
    const char *cursor=compact;int zero=0;
    while(*cursor){char *end;long v=strtol(cursor,&end,10);if(!isdigit((unsigned char)*cursor)||end==cursor||v<0||v>3650||(*end&&*end!=',')||p->count==64)return fail(err,n,"Soglie non valide: numeri distinti da 0 a 3650; includi 0.");for(int i=0;i<p->count;i++)if(p->values[i]==v)return fail(err,n,"Soglie duplicate.");p->values[p->count++]=(int)v;if(!v)zero=1;cursor=*end?end+1:end;if(*end&&!*cursor)return fail(err,n,"Soglie non valide.");}
    if(!p->count||!zero)return fail(err,n,"Le soglie devono includere 0.");
    for(int i=0;i<p->count;i++)for(int j=i+1;j<p->count;j++)if(p->values[j]>p->values[i]){int v=p->values[i];p->values[i]=p->values[j];p->values[j]=v;}
    size_t pos=0;for(int i=0;i<p->count;i++)pos+=(size_t)snprintf(p->thresholds+pos,sizeof p->thresholds-pos,"%s%d",i?",":"",p->values[i]);
    snprintf(p->email,sizeof p->email,"%s",email);snprintf(p->name,sizeof p->name,"%s",name);p->enabled=(int)enabled;p->days=(int)days;return 1;
}
static void policy_json(FILE*out,const Policy*p) {fputs("{\"thresholds\":",out);app_json_string(out,p->thresholds);fprintf(out,",\"enabled\":%d,\"escalation_after_days\":%d,\"escalation_email\":",p->enabled,p->days);app_json_string(out,p->email);fputs(",\"escalation_name\":",out);app_json_string(out,p->name);fputc('}',out);}
static int reminder_preview(Store*s,const WFForm*f,FILE*out,char*err,size_t n) {
    int64_t id=0;if(!wf_number(wf_get(f,"certificate_id"),1,INT64_MAX,&id))return fail(err,n,"Certificato non valido.");Policy p;if(!parse_policy(f,&p,err,n))return 0;
    sqlite3_stmt*q=NULL;if(!prep(s,&q,"SELECT not_after,archived FROM certificates WHERE id=?1",err,n))return 0;sqlite3_bind_int64(q,1,id);if(sqlite3_step(q)!=SQLITE_ROW){sqlite3_finalize(q);return fail(err,n,"Certificato non trovato.");}int64_t expiry=sqlite3_column_int64(q,0),now=(int64_t)time(NULL);int archived=sqlite3_column_int(q,1);sqlite3_finalize(q);q=NULL;
    unsigned char recorded[3651]={0};int minimum=3651;int64_t first_notice=0;
    if(!prep(s,&q,"SELECT threshold,sent_at FROM notifications WHERE certificate_id=?1",err,n))return 0;sqlite3_bind_int64(q,1,id);int rc;
    while((rc=sqlite3_step(q))==SQLITE_ROW){int v=sqlite3_column_int(q,0);if(v>=0&&v<=3650){recorded[v]=1;if(v<minimum)minimum=v;}int64_t at=sqlite3_column_int64(q,1);if(!first_notice||at<first_notice)first_notice=at;}sqlite3_finalize(q);if(rc!=SQLITE_DONE)return dbfail(s,err,n);
    int due=-1;for(int i=0;i<p.count;i++)if(expiry-(int64_t)p.values[i]*86400<=now&&(due<0||p.values[i]<due))due=p.values[i];
    fprintf(out,"{\"certificate_id\":%"PRId64",\"now\":%"PRId64",\"days_left\":%"PRId64",\"archived\":%s,\"policy\":",id,now,app_days_remaining(expiry,now),archived?"true":"false");policy_json(out,&p);fputs(",\"events\":[",out);
    int64_t first_future=0;int immediate=due>=0&&minimum>due&&p.enabled&&!archived;
    for(int i=0;i<p.count;i++){int v=p.values[i];int64_t at=expiry-(int64_t)v*86400;const char*state;
        if(recorded[v])state="recorded";else if(!p.enabled||archived)state="disabled";else if(v>=minimum)state="superseded";else if(at>now)state="future";else if(v==due&&immediate)state="immediate";else state="skipped";
        if(!strcmp(state,"future")&&(!first_future||at<first_future))first_future=at;
        if(i)fputc(',',out);fprintf(out,"{\"threshold\":%d,\"scheduled_at\":%"PRId64",\"at\":%"PRId64",\"status\":",v,at,!strcmp(state,"immediate")?now:at);app_json_string(out,state);fputc('}',out);
    }
    fputs("],\"recipients\":",out);if(!wf_json_rows(s,out,"SELECT name,email FROM contacts WHERE certificate_id=?1 AND role='business' ORDER BY email",id,err,n))return 0;
    int64_t base=first_notice?first_notice:(immediate?now:first_future),esc_at=base?base+(int64_t)p.days*86400:0;
    int esc_recorded=0;if(*p.email){if(!prep(s,&q,"SELECT EXISTS(SELECT 1 FROM outbox WHERE certificate_id=?1 AND kind='escalation' AND recipient_email=?2 COLLATE NOCASE)",err,n))return 0;sqlite3_bind_int64(q,1,id);text(q,2,p.email);if(sqlite3_step(q)!=SQLITE_ROW){sqlite3_finalize(q);return dbfail(s,err,n);}esc_recorded=sqlite3_column_int(q,0);sqlite3_finalize(q);}
    const char*esc_status=(!p.enabled||archived||!*p.email)?"disabled":esc_recorded?"recorded":!esc_at?"awaiting_first_reminder":esc_at<=now?"immediate":"future";
    fputs(",\"escalation\":{\"email\":",out);app_json_string(out,p.email);fputs(",\"name\":",out);app_json_string(out,p.name);fprintf(out,",\"after_days\":%d,\"at\":",p.days);if(esc_at)fprintf(out,"%"PRId64,esc_at<=now?now:esc_at);else fputs("null",out);fputs(",\"status\":",out);app_json_string(out,esc_status);fputs("}}",out);return 1;
}

static int compare(Store*s,const WFForm*f,FILE*out,char*err,size_t n) {
    int64_t old_id,new_id;if(!wf_number(wf_get(f,"old_certificate_id"),1,INT64_MAX,&old_id)||!wf_number(wf_get(f,"new_certificate_id"),1,INT64_MAX,&new_id))return fail(err,n,"Seleziona due certificati.");
    int candidate=0;if(!lifecycle_is_candidate(s,old_id,new_id,&candidate,err,n))return 0;fprintf(out,"{\"candidate\":%s,\"previous\":",candidate?"true":"false");if(!object(s,out,certificate_sql,old_id,err,n))return 0;fputs(",\"next\":",out);if(!object(s,out,certificate_sql,new_id,err,n))return 0;
    sqlite3_stmt*q=NULL;if(!prep(s,&q,"SELECT a.common_name=b.common_name,a.sans=b.sans,a.issuer=b.issuer,a.not_before=b.not_before,a.not_after=b.not_after,a.fingerprint=b.fingerprint,a.key_algorithm=b.key_algorithm AND a.key_bits=b.key_bits,a.signature_algorithm=b.signature_algorithm FROM certificates a JOIN certificates b ON b.id=?2 WHERE a.id=?1",err,n))return 0;sqlite3_bind_int64(q,1,old_id);sqlite3_bind_int64(q,2,new_id);if(sqlite3_step(q)!=SQLITE_ROW){sqlite3_finalize(q);return dbfail(s,err,n);}const char*fields[]={"common_name","sans","issuer","not_before","not_after","fingerprint","key","signature_algorithm"};fputs(",\"differences\":[",out);int first=1;for(int i=0;i<8;i++)if(!sqlite3_column_int(q,i)){if(!first)fputc(',',out);first=0;app_json_string(out,fields[i]);}fputs("],\"identity_matches\":",out);sqlite3_finalize(q);
    if(!prep(s,&q,"SELECT a.common_name,a.sans,b.common_name,b.sans FROM certificates a JOIN certificates b ON b.id=?2 WHERE a.id=?1",err,n))return 0;sqlite3_bind_int64(q,1,old_id);sqlite3_bind_int64(q,2,new_id);if(sqlite3_step(q)!=SQLITE_ROW){sqlite3_finalize(q);return dbfail(s,err,n);}Certificate a={0},b={0};a.common_name=(char*)sqlite3_column_text(q,0);a.sans=(char*)sqlite3_column_text(q,1);b.common_name=(char*)sqlite3_column_text(q,2);b.sans=(char*)sqlite3_column_text(q,3);char mismatch[512]="";int match=chain_renewal_matches(&a,&b,mismatch,sizeof mismatch);fprintf(out,"%s,\"identity_message\":",match?"true":"false");app_json_string(out,mismatch);sqlite3_finalize(q);
    fputs(",\"previous_chain\":",out);CertificateChain chain={0};if(!chain_describe(s,old_id,&chain,err,n))return 0;fputs("{\"root_ca\":",out);app_json_string(out,chain.root_ca);fputs(",\"intermediate_ca\":",out);app_json_string(out,chain.intermediate_ca);fputc('}',out);chain_free(&chain);fputs(",\"next_chain\":",out);if(!chain_describe(s,new_id,&chain,err,n))return 0;fputs("{\"root_ca\":",out);app_json_string(out,chain.root_ca);fputs(",\"intermediate_ca\":",out);app_json_string(out,chain.intermediate_ca);fputs("}}",out);chain_free(&chain);return 1;
}
static int ids(const WFForm *,const char *,int64_t *,size_t *,char *,size_t);
static int proposed_directory(Store *s,const WFForm *f,FILE *out,int group,int64_t id,char *err,size_t n) {
    if(!wf_count(f,"proposed")){fputs(",\"proposal\":null",out);return 1;}
    if(!wf_get(f,"proposed")||strcmp(wf_get(f,"proposed"),"1"))return fail(err,n,"Proposta di modifica non valida.");
    const char *name=wf_get(f,"name"),*email=group?"":wf_get(f,"email");
    if(!plain(name,120)||(group&&!*name)||(!group&&!store_email_valid(email)))return fail(err,n,"Nome o indirizzo proposto non valido.");
    int64_t members[1000];size_t count=0;const char *key=group?"person_id":"group_id";
    if(!ids(f,key,members,&count,err,n))return 0;
    char list[22000]="NULL";size_t used=0;
    sqlite3_stmt *q=NULL;
    for(size_t i=0;i<count;i++){
        if(!prep(s,&q,group?"SELECT 1 FROM directory_people WHERE id=?1":"SELECT 1 FROM directory_groups WHERE id=?1",err,n))return 0;
        sqlite3_bind_int64(q,1,members[i]);int found=sqlite3_step(q)==SQLITE_ROW;sqlite3_finalize(q);q=NULL;
        if(!found)return fail(err,n,"Persona o gruppo proposto non trovato.");
        used+=(size_t)snprintf(list+used,sizeof list-used,"%s%"PRId64,i?",":"",members[i]);
    }
    fputs(",\"proposal\":{\"name\":",out);app_json_string(out,name);fputs(",\"email\":",out);app_json_string(out,email);
    fputs(",\"memberships_before\":",out);
    if(!wf_json_rows(s,out,group?"SELECT p.id,p.name,p.email FROM directory_memberships m JOIN directory_people p ON p.id=m.person_id WHERE m.group_id=?1 ORDER BY p.id":"SELECT g.id,g.name FROM directory_memberships m JOIN directory_groups g ON g.id=m.group_id WHERE m.person_id=?1 ORDER BY g.id",id,err,n))return 0;
    char *sql=sqlite3_mprintf(group?"SELECT id,name,email FROM directory_people WHERE id IN(%s) ORDER BY id":"SELECT id,name FROM directory_groups WHERE id IN(%s) ORDER BY id",list);
    if(!sql)return fail(err,n,"Memoria insufficiente.");fputs(",\"memberships_after\":",out);int ok=wf_json_rows(s,out,sql,0,err,n);sqlite3_free(sql);if(!ok)return 0;
    fputs(",\"certificates\":",out);
    sql=group?sqlite3_mprintf("SELECT DISTINCT c.id AS certificate_id,c.common_name,g.role FROM certificate_groups g JOIN certificates c ON c.id=g.certificate_id WHERE g.group_id=?1 ORDER BY c.id,g.role"):
        sqlite3_mprintf("SELECT DISTINCT c.id AS certificate_id,c.common_name,a.role FROM directory_assignments a JOIN certificates c ON c.id=a.certificate_id WHERE a.person_id=?1 AND a.group_id=0 UNION SELECT c.id,c.common_name,g.role FROM certificate_groups g JOIN certificates c ON c.id=g.certificate_id WHERE g.group_id IN(%s) UNION SELECT c.id,c.common_name,'escalation' FROM reminder_policies p JOIN certificates c ON c.id=p.certificate_id JOIN directory_people d ON d.email=p.escalation_email COLLATE NOCASE WHERE d.id=?1 UNION SELECT c.id,c.common_name,'monitor' FROM monitor_recipients r JOIN monitors m ON m.id=r.monitor_id JOIN certificates c ON c.id=m.certificate_id JOIN directory_people d ON d.email=r.email COLLATE NOCASE WHERE d.id=?1 ORDER BY 1,3",list);
    if(!sql)return fail(err,n,"Memoria insufficiente.");ok=wf_json_rows(s,out,sql,id,err,n);sqlite3_free(sql);if(!ok)return 0;fputc('}',out);return 1;
}
static int directory_impact(Store*s,const WFForm*f,FILE*out,char*err,size_t n) {
    const char*type=wf_get(f,"type");int64_t id;if(!type||(strcmp(type,"person")&&strcmp(type,"group"))||!wf_number(wf_get(f,"id"),1,INT64_MAX,&id))return fail(err,n,"Persona o gruppo non valido.");int group=!strcmp(type,"group");fprintf(out,"{\"type\":");app_json_string(out,type);fprintf(out,",\"id\":%"PRId64",\"item\":",id);if(!object(s,out,group?"SELECT * FROM directory_groups WHERE id=?1":"SELECT * FROM directory_people WHERE id=?1",id,err,n))return 0;
    fputs(",\"people\":",out);if(!wf_json_rows(s,out,group?"SELECT p.* FROM directory_people p JOIN directory_memberships m ON m.person_id=p.id WHERE m.group_id=?1 ORDER BY p.email":"SELECT * FROM directory_people WHERE id=?1",id,err,n))return 0;
    fputs(",\"certificates\":",out);if(!wf_json_rows(s,out,group?
        "SELECT DISTINCT c.id AS certificate_id,c.common_name,g.role FROM certificate_groups g JOIN certificates c ON c.id=g.certificate_id WHERE g.group_id=?1 ORDER BY c.id,g.role":
        "SELECT DISTINCT c.id AS certificate_id,c.common_name,a.role FROM directory_assignments a JOIN certificates c ON c.id=a.certificate_id WHERE a.person_id=?1 UNION SELECT c.id,c.common_name,'escalation' FROM reminder_policies p JOIN certificates c ON c.id=p.certificate_id JOIN directory_people d ON d.email=p.escalation_email COLLATE NOCASE WHERE d.id=?1 UNION SELECT c.id,c.common_name,'monitor' FROM monitor_recipients r JOIN monitors m ON m.id=r.monitor_id JOIN certificates c ON c.id=m.certificate_id JOIN directory_people d ON d.email=r.email COLLATE NOCASE WHERE d.id=?1 ORDER BY 1,3",id,err,n))return 0;
    fputs(",\"pending_mail\":",out);if(!wf_json_rows(s,out,group?
        "SELECT DISTINCT o.id,o.certificate_id,o.kind,o.recipient_name,o.recipient_email,o.status FROM outbox o JOIN certificate_groups g ON g.certificate_id=o.certificate_id JOIN directory_memberships m ON m.group_id=g.group_id JOIN directory_people p ON p.id=m.person_id AND p.email=o.recipient_email COLLATE NOCASE WHERE g.group_id=?1 AND o.status IN('pending','failed') AND ((o.template_copy=0 AND ((g.role='business' AND o.kind='expiry') OR (g.role='technical' AND o.kind='certificate'))) OR (o.template_copy=1 AND o.template_audience=g.role)) ORDER BY o.id":
        "SELECT o.id,o.certificate_id,o.kind,o.recipient_name,o.recipient_email,o.status FROM outbox o JOIN directory_people p ON p.email=o.recipient_email COLLATE NOCASE WHERE p.id=?1 AND o.status IN('pending','failed') AND NOT(o.template_copy=1 AND o.template_audience='self') ORDER BY o.id",id,err,n))return 0;
    fputs(",\"monitor_recipients\":",out);if(!wf_json_rows(s,out,group?
        "SELECT DISTINCT r.monitor_id,m.target,r.email FROM monitor_recipients r JOIN monitors m ON m.id=r.monitor_id JOIN directory_people p ON p.email=r.email COLLATE NOCASE JOIN directory_memberships g ON g.person_id=p.id WHERE g.group_id=?1 ORDER BY r.monitor_id,r.email":
        "SELECT r.monitor_id,m.target,r.email FROM monitor_recipients r JOIN monitors m ON m.id=r.monitor_id JOIN directory_people p ON p.email=r.email COLLATE NOCASE WHERE p.id=?1 ORDER BY r.monitor_id",id,err,n))return 0;
    if(!proposed_directory(s,f,out,group,id,err,n))return 0;
    fputc('}',out);return 1;
}

static int template_load(Store*s,int64_t id,Policy*p,char*err,size_t n) {
    sqlite3_stmt*q=NULL;if(!prep(s,&q,"SELECT thresholds,enabled,escalation_email,escalation_name,escalation_after_days FROM policy_templates WHERE id=?1",err,n))return 0;sqlite3_bind_int64(q,1,id);if(sqlite3_step(q)!=SQLITE_ROW){sqlite3_finalize(q);return fail(err,n,"Modello non trovato.");}memset(p,0,sizeof*p);snprintf(p->thresholds,sizeof p->thresholds,"%s",sqlite3_column_text(q,0));p->enabled=sqlite3_column_int(q,1);snprintf(p->email,sizeof p->email,"%s",sqlite3_column_text(q,2));snprintf(p->name,sizeof p->name,"%s",sqlite3_column_text(q,3));p->days=sqlite3_column_int(q,4);sqlite3_finalize(q);return 1;
}
static int template_save(Store*s,int64_t id,const WFForm*f,FILE*out,char*err,size_t n) {
    Policy p;if(!parse_policy(f,&p,err,n))return 0;const char*name=wf_get(f,"name");if(!plain(name,120)||!*name)return fail(err,n,"Nome modello non valido.");
    if(!store_exec(s,"SAVEPOINT operations",err,n))return 0;sqlite3_stmt*q=NULL;int ok=0;
    if(id){Policy existing;if(!template_load(s,id,&existing,err,n))goto end;}
    if(!prep(s,&q,id?"UPDATE policy_templates SET name=?1,thresholds=?2,enabled=?3,escalation_email=?4,escalation_name=?5,escalation_after_days=?6,updated_at=?7 WHERE id=?8":"INSERT INTO policy_templates(name,thresholds,enabled,escalation_email,escalation_name,escalation_after_days,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",err,n))goto end;
    text(q,1,name);text(q,2,p.thresholds);sqlite3_bind_int(q,3,p.enabled);text(q,4,p.email);text(q,5,p.name);sqlite3_bind_int(q,6,p.days);sqlite3_bind_int64(q,7,(int64_t)time(NULL));if(id)sqlite3_bind_int64(q,8,id);if(!done(s,&q,err,n))goto end;if(!id)id=sqlite3_last_insert_rowid(s->db);ok=wf_audit(s,"policy_template",id,"save",name,err,n);
end:sqlite3_finalize(q);ok=finish(s,ok,err,n);if(ok)fprintf(out,"{\"id\":%"PRId64"}",id);return ok;
}
static int template_remove(Store*s,int64_t id,FILE*out,char*err,size_t n) {
    Policy p;if(!template_load(s,id,&p,err,n))return 0;if(!store_exec(s,"SAVEPOINT operations",err,n))return 0;sqlite3_stmt*q=NULL;int ok=prep(s,&q,"DELETE FROM policy_templates WHERE id=?1",err,n);if(ok){sqlite3_bind_int64(q,1,id);ok=done(s,&q,err,n);}if(ok)ok=wf_audit(s,"policy_template",id,"delete","",err,n);ok=finish(s,ok,err,n);if(ok)fputs("{\"ok\":true}",out);return ok;
}
static int ids(const WFForm*f,const char*key,int64_t *values,size_t*count,char*err,size_t n) {
    *count=wf_count(f,key);if(*count>1000)return fail(err,n,"Massimo 1000 certificati per operazione.");for(size_t i=0;i<*count;i++){if(!wf_number(wf_nth(f,key,i),1,INT64_MAX,&values[i]))return fail(err,n,"Identificativo certificato non valido.");for(size_t j=0;j<i;j++)if(values[j]==values[i])return fail(err,n,"Identificativo certificato duplicato.");}for(size_t i=0;i<*count;i++)for(size_t j=i+1;j<*count;j++)if(values[j]<values[i]){int64_t v=values[i];values[i]=values[j];values[j]=v;}return 1;
}
static int contains(const int64_t*ids,size_t count,int64_t id) {for(size_t i=0;i<count;i++)if(ids[i]==id)return 1;return 0;}
static void hash_text(const char*json,size_t length,char hex[65]) {unsigned char digest[SHA256_DIGEST_LENGTH];SHA256((const unsigned char*)json,length,digest);for(size_t i=0;i<sizeof digest;i++)snprintf(hex+i*2,3,"%02x",digest[i]);}
static int template_plan(Store*s,int64_t template_id,const WFForm*f,FILE*out,int apply,char*err,size_t n) {
    int64_t certs[1000],excluded[1000];size_t count,ec;if(!ids(f,"certificate_id",certs,&count,err,n)||!ids(f,"exclude_id",excluded,&ec,err,n))return 0;if(!count||ec>=count)return fail(err,n,"Seleziona almeno un certificato da aggiornare.");for(size_t i=0;i<ec;i++)if(!contains(certs,count,excluded[i]))return fail(err,n,"Le eccezioni devono appartenere ai certificati selezionati.");
    if(!store_exec(s,"SAVEPOINT operations",err,n))return 0;Policy p;int ok=0;sqlite3_stmt*q=NULL;char*plan=NULL;size_t length=0;FILE*stream=NULL;
    if(!template_load(s,template_id,&p,err,n))goto end;stream=open_memstream(&plan,&length);if(!stream){fail(err,n,"Memoria insufficiente.");goto end;}
    fprintf(stream,"{\"template_id\":%"PRId64",\"changes\":[",template_id);
    for(size_t i=0;i<count;i++) {
        if(!prep(s,&q,"SELECT common_name,is_ca,archived FROM certificates WHERE id=?1",err,n))goto end;sqlite3_bind_int64(q,1,certs[i]);if(sqlite3_step(q)!=SQLITE_ROW){fail(err,n,"Certificato non trovato.");goto end;}
        int skip=contains(excluded,ec,certs[i]);if(!skip&&(sqlite3_column_int(q,1)||sqlite3_column_int(q,2))){fail(err,n,"I modelli possono aggiornare solo certificati finali attivi.");goto end;}
        if(i)fputc(',',stream);fprintf(stream,"{\"certificate_id\":%"PRId64",\"common_name\":",certs[i]);app_json_string(stream,(const char*)sqlite3_column_text(q,0));fprintf(stream,",\"excluded\":%s,\"before\":",skip?"true":"false");sqlite3_finalize(q);q=NULL;
        if(!object(s,stream,policy_before_sql,certs[i],err,n))goto end;
        fputs(",\"after\":",stream);if(skip){if(!object(s,stream,policy_before_sql,certs[i],err,n))goto end;}else policy_json(stream,&p);fputc('}',stream);
    }
    fputs("]}",stream);if(ferror(stream)){fail(err,n,"Errore preparazione riepilogo.");goto end;}if(fclose(stream)){stream=NULL;fail(err,n,"Errore preparazione riepilogo.");goto end;}stream=NULL;
    char hash[65];hash_text(plan,length,hash);
    if(apply){const char*expected=wf_get(f,"plan_hash");if(!expected||strlen(expected)!=64||strcmp(expected,hash)){fail(err,n,"Il riepilogo è cambiato: genera una nuova anteprima prima di applicare.");goto end;}
        for(size_t i=0;i<count;i++)if(!contains(excluded,ec,certs[i])){if(!workspace_save_policy(s,certs[i],p.thresholds,p.enabled,p.email,p.name,p.days,err,n)||!wf_audit(s,"certificate",certs[i],"policy_template_apply",plan,err,n))goto end;}
    }
    /* Embed the canonical plan and bind confirmation to every before/after value. */
    if(length&&plan[length-1]=='}')plan[length-1]=0;fputs(plan,out);fputs(",\"plan_hash\":",out);app_json_string(out,hash);fprintf(out,",\"applied\":%s}",apply?"true":"false");ok=1;
end:sqlite3_finalize(q);if(stream)fclose(stream);free(plan);return finish(s,ok,err,n);
}
static int delivery(Store*s,int64_t id,FILE*out,char*err,size_t n) {
    sqlite3_stmt *exists=NULL;if(!prep(s,&exists,"SELECT 1 FROM renewal_jobs WHERE id=?1",err,n))return 0;sqlite3_bind_int64(exists,1,id);int found=sqlite3_step(exists)==SQLITE_ROW;sqlite3_finalize(exists);if(!found)return fail(err,n,"Pratica di rinnovo non trovata.");
    fprintf(out,"{\"job_id\":%"PRId64",\"recipients\":",id);
    if(!wf_json_rows(s,out,"SELECT c.name,c.email,o.id AS outbox_id,coalesce(o.status,'not_queued') AS status,coalesce(o.attempts,0) AS attempts,coalesce(o.last_error,'') AS last_error,o.sent_at,coalesce(o.status='sent',0) AS smtp_accepted FROM renewal_jobs j JOIN contacts c ON c.certificate_id=j.new_certificate_id AND c.role='technical' LEFT JOIN outbox o ON o.certificate_id=j.new_certificate_id AND o.kind='certificate' AND o.recipient_email=c.email COLLATE NOCASE WHERE j.id=?1 UNION SELECT o.recipient_name,o.recipient_email,o.id,o.status,o.attempts,o.last_error,o.sent_at,o.status='sent' FROM renewal_jobs j JOIN outbox o ON o.certificate_id=j.new_certificate_id AND o.kind='certificate' WHERE j.id=?1 AND NOT EXISTS(SELECT 1 FROM contacts c WHERE c.certificate_id=j.new_certificate_id AND c.role='technical' AND c.email=o.recipient_email COLLATE NOCASE) ORDER BY 2",id,err,n))return 0;
    fputs(",\"smtp_acceptance_is_installation\":false}",out);return 1;
}
static int report_body(Store*s,int64_t id,FILE*out,char*err,size_t n) {
    fputs("{\"renewal\":",out);if(!object(s,out,"SELECT * FROM renewal_jobs WHERE id=?1",id,err,n))return 0;
    sqlite3_stmt*q=NULL;if(!prep(s,&q,"SELECT old_certificate_id,coalesce(new_certificate_id,0) FROM renewal_jobs WHERE id=?1",err,n))return 0;sqlite3_bind_int64(q,1,id);if(sqlite3_step(q)!=SQLITE_ROW){sqlite3_finalize(q);return fail(err,n,"Pratica non trovata.");}int64_t old_id=sqlite3_column_int64(q,0),new_id=sqlite3_column_int64(q,1);sqlite3_finalize(q);
    fputs(",\"previous\":",out);if(!object(s,out,certificate_sql,old_id,err,n))return 0;fputs(",\"next\":",out);if(new_id){if(!object(s,out,certificate_sql,new_id,err,n))return 0;}else fputs("null",out);
    fputs(",\"checklist\":",out);int allowed;if(!lifecycle_checklist(s,id,out,&allowed,err,n))return 0;fputs(",\"delivery\":",out);if(!delivery(s,id,out,err,n))return 0;
    fputs(",\"audit\":",out);if(!wf_json_rows(s,out,"SELECT * FROM workflow_audit WHERE (entity_type='renewal' AND entity_id=?1) OR (entity_type='certificate' AND entity_id IN(SELECT old_certificate_id FROM renewal_jobs WHERE id=?1 UNION SELECT new_certificate_id FROM renewal_jobs WHERE id=?1)) OR (entity_type='monitor' AND entity_id IN(SELECT monitor_id FROM renewal_endpoints WHERE job_id=?1)) ORDER BY id",id,err,n))return 0;
    fputs(",\"actor_model\":\"local_without_authentication\"}",out);return 1;
}
int operations_capture_report(Store*s,int64_t id,const char*mode,char*err,size_t n) {
    if(strcmp(mode,"verified")&&strcmp(mode,"retired"))return fail(err,n,"Modalità chiusura non valida.");
    char*json=NULL;size_t length=0;FILE*out=open_memstream(&json,&length);if(!out)return fail(err,n,"Memoria insufficiente.");int ok=report_body(s,id,out,err,n);if(fclose(out))ok=0;
    sqlite3_stmt*q=NULL;if(ok)ok=prep(s,&q,"INSERT INTO renewal_closure_reports(job_id,mode,captured_at,report_json) VALUES(?1,?2,?3,?4) ON CONFLICT(job_id) DO NOTHING",err,n);if(ok){sqlite3_bind_int64(q,1,id);text(q,2,mode);sqlite3_bind_int64(q,3,(int64_t)time(NULL));text(q,4,json);ok=done(s,&q,err,n);}sqlite3_finalize(q);free(json);return ok;
}
static int report(Store*s,int64_t id,FILE*out,char*err,size_t n) {
    fputs("{\"live\":",out);if(!report_body(s,id,out,err,n))return 0;fputs(",\"closure\":",out);sqlite3_stmt*q=NULL;if(!prep(s,&q,"SELECT mode,captured_at,report_json FROM renewal_closure_reports WHERE job_id=?1",err,n))return 0;sqlite3_bind_int64(q,1,id);int rc=sqlite3_step(q);if(rc==SQLITE_ROW){fputs("{\"mode\":",out);app_json_string(out,(const char*)sqlite3_column_text(q,0));fprintf(out,",\"captured_at\":%lld,\"evidence\":",(long long)sqlite3_column_int64(q,1));fputs((const char*)sqlite3_column_text(q,2),out);fputc('}',out);}else if(rc==SQLITE_DONE)fputs("null",out);else{sqlite3_finalize(q);return dbfail(s,err,n);}sqlite3_finalize(q);fputc('}',out);return 1;
}
static int route_id(const char*path,const char*prefix,int64_t*id,const char**suffix) {
    size_t len=strlen(prefix);if(strncmp(path,prefix,len))return 0;const char*p=path+len,*end=p;while(isdigit((unsigned char)*end))end++;if(end==p||(*end&&*end!='/')||end-p>19)return 0;char value[24];memcpy(value,p,(size_t)(end-p));value[end-p]=0;if(!wf_number(value,1,INT64_MAX,id))return 0;*suffix=end;return 1;
}
char *operations_api(Store*s,const char*method,const char*path,const unsigned char*body,size_t bodylen,size_t*length,int*status,char*err,size_t n) {
    *status=400;WFForm f={0};char*json=NULL;FILE*out=NULL;int ok=0;int64_t id=0;const char*suffix=NULL;
    if(strcmp(method,"GET")&&strcmp(method,"POST")&&strcmp(method,"PUT")&&strcmp(method,"DELETE")){*status=405;fail(err,n,"Metodo non consentito.");return NULL;}
    if(bodylen&&!wf_form_parse(body,bodylen,&f,err,n))return NULL;
    int outer=sqlite3_get_autocommit(s->db);
    if(!store_exec(s,"SAVEPOINT operations_api_view",err,n)){wf_form_free(&f);return NULL;}
    out=open_memstream(&json,length);if(!out){sqlite3_exec(s->db,outer?"ROLLBACK":"ROLLBACK TO operations_api_view; RELEASE operations_api_view",NULL,NULL,NULL);wf_form_free(&f);fail(err,n,"Memoria insufficiente.");return NULL;}
    if(!strcmp(path,"/api/operations/compare")&&!strcmp(method,"POST"))ok=compare(s,&f,out,err,n);
    else if(!strcmp(path,"/api/operations/directory-impact")&&!strcmp(method,"POST"))ok=directory_impact(s,&f,out,err,n);
    else if(!strcmp(path,"/api/operations/reminder-preview")&&!strcmp(method,"POST"))ok=reminder_preview(s,&f,out,err,n);
    else if(!strcmp(path,"/api/operations/templates")&&!strcmp(method,"GET")){fputs("{\"templates\":",out);ok=wf_json_rows(s,out,"SELECT * FROM policy_templates ORDER BY name,id",0,err,n);fputc('}',out);}
    else if(!strcmp(path,"/api/operations/templates")&&!strcmp(method,"POST"))ok=template_save(s,0,&f,out,err,n);
    else if(route_id(path,"/api/operations/templates/",&id,&suffix)){
        if(!*suffix&&!strcmp(method,"PUT"))ok=template_save(s,id,&f,out,err,n);
        else if(!*suffix&&!strcmp(method,"DELETE"))ok=template_remove(s,id,out,err,n);
        else if(!strcmp(suffix,"/plan")&&!strcmp(method,"POST"))ok=template_plan(s,id,&f,out,0,err,n);
        else if(!strcmp(suffix,"/apply")&&!strcmp(method,"POST"))ok=template_plan(s,id,&f,out,1,err,n);
        else{*status=405;fail(err,n,"Metodo non consentito.");}
    }
    else if(route_id(path,"/api/operations/renewals/",&id,&suffix)&&!strcmp(method,"GET")){
        if(!strcmp(suffix,"/checklist")){int allowed;ok=lifecycle_checklist(s,id,out,&allowed,err,n);}
        else if(!strcmp(suffix,"/delivery"))ok=delivery(s,id,out,err,n);
        else if(!strcmp(suffix,"/report"))ok=report(s,id,out,err,n);
        else{*status=404;fail(err,n,"Risorsa non trovata.");}
    }
    else{*status=404;fail(err,n,"Risorsa non trovata.");}
    if(ferror(out))ok=0;if(fclose(out))ok=0;wf_form_free(&f);if(ok)ok=store_exec(s,"RELEASE operations_api_view",err,n);if(!ok){sqlite3_exec(s->db,outer?"ROLLBACK":"ROLLBACK TO operations_api_view; RELEASE operations_api_view",NULL,NULL,NULL);free(json);return NULL;}*status=200;return json;
}
