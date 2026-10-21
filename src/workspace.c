#define _POSIX_C_SOURCE 200809L
#include "workspace.h"
#include "app.h"
#include "chain.h"
#include "lifecycle.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <inttypes.h>

static int failure(Store *s, char *err, size_t n) {
    snprintf(err,n,"%s",sqlite3_errmsg(s->db)); return 0;
}
static int text_valid(const char *text, size_t maximum) {
    if (!text || strlen(text)>maximum) return 0;
    for (const unsigned char *p=(const unsigned char *)text;*p;p++) if (*p<32 || *p==127) return 0;
    return 1;
}
static int statement(Store *s,const char *sql,int64_t id,char *err,size_t n) {
    sqlite3_stmt *q=NULL;
    int ok=sqlite3_prepare_v2(s->db,sql,-1,&q,NULL)==SQLITE_OK;
    if(ok && sqlite3_bind_parameter_count(q)) ok=sqlite3_bind_int64(q,1,id)==SQLITE_OK;
    if(ok) ok=sqlite3_step(q)==SQLITE_DONE;
    if(!ok) failure(s,err,n);
    sqlite3_finalize(q);return ok;
}
static int finish(Store *s,int ok,int outer,char *err,size_t n) {
    if(ok) ok=store_exec(s,"RELEASE workspace",err,n);
    if(!ok) sqlite3_exec(s->db,outer?"ROLLBACK":"ROLLBACK TO workspace; RELEASE workspace",NULL,NULL,NULL);
    return ok;
}
static int exists(Store *s,const char *table,int64_t id) {
    char sql[128];sqlite3_stmt *q=NULL;
    snprintf(sql,sizeof sql,"SELECT 1 FROM %s WHERE id=?1",table);
    int ok=sqlite3_prepare_v2(s->db,sql,-1,&q,NULL)==SQLITE_OK && sqlite3_bind_int64(q,1,id)==SQLITE_OK && sqlite3_step(q)==SQLITE_ROW;
    sqlite3_finalize(q);return ok;
}
static int materialize(Store *s,char *err,size_t n) {
    const char *sql=
        "DELETE FROM directory_assignments WHERE group_id<>0;"
        "INSERT OR IGNORE INTO directory_assignments(certificate_id,role,person_id,group_id) SELECT c.certificate_id,c.role,m.person_id,c.group_id FROM certificate_groups c JOIN directory_memberships m ON m.group_id=c.group_id;"
        "DELETE FROM contacts;"
        "INSERT INTO contacts(certificate_id,role,name,email) SELECT DISTINCT a.certificate_id,a.role,p.name,p.email FROM directory_assignments a JOIN directory_people p ON p.id=a.person_id;"
        "DELETE FROM outbox WHERE status IN('pending','failed') AND kind IN('expiry','certificate') AND NOT EXISTS(SELECT 1 FROM contacts c WHERE c.certificate_id=outbox.certificate_id AND c.email=outbox.recipient_email COLLATE NOCASE AND c.role=CASE outbox.kind WHEN 'expiry' THEN 'business' ELSE 'technical' END);";
    if(!store_exec(s,sql,err,n)) return 0;
    sqlite3_stmt *q=NULL;
    int ok=sqlite3_prepare_v2(s->db,"SELECT 1 FROM contacts GROUP BY certificate_id HAVING count(*)>100 LIMIT 1",-1,&q,NULL)==SQLITE_OK;
    if(ok){int rc=sqlite3_step(q);if(rc==SQLITE_ROW){snprintf(err,n,"Massimo 100 referenti per certificato.");ok=0;}else if(rc!=SQLITE_DONE)ok=failure(s,err,n);}
    sqlite3_finalize(q);return ok;
}
int workspace_contacts_saved(Store *s,int64_t id,char *err,size_t n) {
    const char *steps[]={
        "INSERT OR IGNORE INTO directory_people(name,email) SELECT name,email FROM contacts WHERE certificate_id=?1",
        /* Editing a name in certificate details also edits its shared person.
           Prefer an actually changed name when the email has both roles. */
        "UPDATE directory_people SET name=(SELECT c.name FROM contacts c WHERE c.certificate_id=?1 AND c.email=directory_people.email COLLATE NOCASE AND c.name<>directory_people.name ORDER BY c.role LIMIT 1) WHERE EXISTS(SELECT 1 FROM contacts c WHERE c.certificate_id=?1 AND c.email=directory_people.email COLLATE NOCASE AND c.name<>directory_people.name)",
        "INSERT OR IGNORE INTO directory_assignments(certificate_id,role,person_id,group_id) SELECT a.certificate_id,a.role,a.person_id,0 FROM directory_assignments a JOIN directory_people p ON p.id=a.person_id JOIN contacts c ON c.certificate_id=a.certificate_id AND c.role=a.role AND c.email=p.email COLLATE NOCASE WHERE a.certificate_id=?1 AND a.group_id<>0 AND EXISTS(SELECT 1 FROM directory_memberships m JOIN directory_people x ON x.id=m.person_id WHERE m.group_id=a.group_id AND NOT EXISTS(SELECT 1 FROM contacts z WHERE z.certificate_id=a.certificate_id AND z.role=a.role AND z.email=x.email COLLATE NOCASE))",
        "DELETE FROM certificate_groups WHERE certificate_id=?1 AND EXISTS(SELECT 1 FROM directory_memberships m JOIN directory_people p ON p.id=m.person_id WHERE m.group_id=certificate_groups.group_id AND NOT EXISTS(SELECT 1 FROM contacts c WHERE c.certificate_id=certificate_groups.certificate_id AND c.role=certificate_groups.role AND c.email=p.email COLLATE NOCASE))",
        "DELETE FROM directory_assignments WHERE certificate_id=?1 AND group_id<>0 AND NOT EXISTS(SELECT 1 FROM certificate_groups g WHERE g.certificate_id=directory_assignments.certificate_id AND g.role=directory_assignments.role AND g.group_id=directory_assignments.group_id)",
        "DELETE FROM directory_assignments WHERE certificate_id=?1 AND NOT EXISTS(SELECT 1 FROM directory_people p JOIN contacts c ON c.email=p.email COLLATE NOCASE WHERE p.id=directory_assignments.person_id AND c.certificate_id=directory_assignments.certificate_id AND c.role=directory_assignments.role)",
        "INSERT OR IGNORE INTO directory_assignments(certificate_id,role,person_id,group_id) SELECT c.certificate_id,c.role,p.id,0 FROM contacts c JOIN directory_people p ON p.email=c.email COLLATE NOCASE WHERE c.certificate_id=?1 AND NOT EXISTS(SELECT 1 FROM directory_assignments a WHERE a.certificate_id=c.certificate_id AND a.role=c.role AND a.person_id=p.id)"
    };
    for(size_t i=0;i<sizeof steps/sizeof steps[0];i++) if(!statement(s,steps[i],id,err,n)) return 0;
    return materialize(s,err,n);
}
static int memberships(Store *s,const char *sql,int64_t id,const int64_t *members,size_t count,const char *table,char *err,size_t n) {
    sqlite3_stmt *q=NULL;
    if(count>1000 || sqlite3_prepare_v2(s->db,sql,-1,&q,NULL)!=SQLITE_OK) return failure(s,err,n);
    int ok=1;
    for(size_t i=0;i<count && ok;i++) {
        if(!exists(s,table,members[i])) {snprintf(err,n,"Persona o gruppo non trovato.");ok=0;break;}
        sqlite3_reset(q);sqlite3_clear_bindings(q);
        ok=sqlite3_bind_int64(q,1,id)==SQLITE_OK && sqlite3_bind_int64(q,2,members[i])==SQLITE_OK && sqlite3_step(q)==SQLITE_DONE;
        if(!ok) failure(s,err,n);
    }
    sqlite3_finalize(q);return ok;
}
int workspace_save_person(Store *s,int64_t id,const char *name,const char *email,const int64_t *groups,size_t count,int64_t *saved,char *err,size_t n) {
    if(!text_valid(name,120)||!store_email_valid(email)||count>1000) {snprintf(err,n,"Nome o indirizzo email della persona non valido.");return 0;}
    if(id && !exists(s,"directory_people",id)) {snprintf(err,n,"Persona non trovata.");return 0;}
    int outer=sqlite3_get_autocommit(s->db);
    if(!store_exec(s,"SAVEPOINT workspace",err,n)) return 0;
    sqlite3_stmt *q=NULL;char *old=NULL;
    if(id && sqlite3_prepare_v2(s->db,"SELECT email FROM directory_people WHERE id=?1",-1,&q,NULL)==SQLITE_OK && sqlite3_bind_int64(q,1,id)==SQLITE_OK && sqlite3_step(q)==SQLITE_ROW) old=strdup((const char *)sqlite3_column_text(q,0));
    sqlite3_finalize(q);q=NULL;
    int ok=sqlite3_prepare_v2(s->db,id?"UPDATE directory_people SET name=?1,email=?2 WHERE id=?3":"INSERT INTO directory_people(name,email) VALUES(?1,?2)",-1,&q,NULL)==SQLITE_OK && sqlite3_bind_text(q,1,name,-1,SQLITE_TRANSIENT)==SQLITE_OK && sqlite3_bind_text(q,2,email,-1,SQLITE_TRANSIENT)==SQLITE_OK;
    if(ok && id) ok=sqlite3_bind_int64(q,3,id)==SQLITE_OK;
    if(ok) ok=sqlite3_step(q)==SQLITE_DONE;
    if(!ok) failure(s,err,n);
    sqlite3_finalize(q);q=NULL;
    if(ok && !id) id=sqlite3_last_insert_rowid(s->db);
    if(ok && old && strcasecmp(old,email)) {
        const char *updates[]={"UPDATE reminder_policies SET escalation_email=?1 WHERE escalation_email=?2 COLLATE NOCASE", "UPDATE OR IGNORE monitor_recipients SET email=?1 WHERE email=?2 COLLATE NOCASE", "UPDATE OR IGNORE outbox SET recipient_email=?1 WHERE recipient_email=?2 COLLATE NOCASE AND status IN('pending','failed')", "DELETE FROM monitor_recipients WHERE email=?2 COLLATE NOCASE", "DELETE FROM outbox WHERE recipient_email=?2 COLLATE NOCASE AND status IN('pending','failed')"};
        for(size_t i=0;i<sizeof updates/sizeof updates[0] && ok;i++) {
            ok=sqlite3_prepare_v2(s->db,updates[i],-1,&q,NULL)==SQLITE_OK && sqlite3_bind_text(q,1,email,-1,SQLITE_TRANSIENT)==SQLITE_OK && sqlite3_bind_text(q,2,old,-1,SQLITE_TRANSIENT)==SQLITE_OK && sqlite3_step(q)==SQLITE_DONE;
            if(!ok) failure(s,err,n);
            sqlite3_finalize(q);q=NULL;
        }
    }
    free(old);
    if(ok) ok=statement(s,"DELETE FROM directory_memberships WHERE person_id=?1",id,err,n) && memberships(s,"INSERT OR IGNORE INTO directory_memberships(person_id,group_id) VALUES(?1,?2)",id,groups,count,"directory_groups",err,n) && materialize(s,err,n);
    ok=finish(s,ok,outer,err,n);if(ok)*saved=id;return ok;
}
int workspace_save_group(Store *s,int64_t id,const char *name,const int64_t *people,size_t count,int64_t *saved,char *err,size_t n) {
    if(!text_valid(name,120)||!*name||count>1000) {snprintf(err,n,"Nome del gruppo non valido.");return 0;}
    if(id&&!exists(s,"directory_groups",id)) {snprintf(err,n,"Gruppo non trovato.");return 0;}
    int outer=sqlite3_get_autocommit(s->db);
    if(!store_exec(s,"SAVEPOINT workspace",err,n)) return 0;
    sqlite3_stmt *q=NULL;
    int ok=sqlite3_prepare_v2(s->db,id?"UPDATE directory_groups SET name=?1 WHERE id=?2":"INSERT INTO directory_groups(name) VALUES(?1)",-1,&q,NULL)==SQLITE_OK && sqlite3_bind_text(q,1,name,-1,SQLITE_TRANSIENT)==SQLITE_OK;
    if(ok&&id)ok=sqlite3_bind_int64(q,2,id)==SQLITE_OK;
    if(ok)ok=sqlite3_step(q)==SQLITE_DONE;
    if(!ok) failure(s,err,n);
    sqlite3_finalize(q);
    if(ok&&!id)id=sqlite3_last_insert_rowid(s->db);
    if(ok)ok=statement(s,"DELETE FROM directory_memberships WHERE group_id=?1",id,err,n)&&memberships(s,"INSERT OR IGNORE INTO directory_memberships(group_id,person_id) VALUES(?1,?2)",id,people,count,"directory_people",err,n)&&materialize(s,err,n);
    ok=finish(s,ok,outer,err,n);if(ok)*saved=id;return ok;
}
int workspace_remove_person(Store *s,int64_t id,char *err,size_t n) {
    if(!exists(s,"directory_people",id)){snprintf(err,n,"Persona non trovata.");return 0;}
    int outer=sqlite3_get_autocommit(s->db);
    if(!store_exec(s,"SAVEPOINT workspace",err,n))return 0;
    int ok=statement(s,"DELETE FROM monitor_recipients WHERE email IN(SELECT email FROM directory_people WHERE id=?1)",id,err,n)&&statement(s,"UPDATE reminder_policies SET escalation_email='' WHERE escalation_email COLLATE NOCASE IN(SELECT email FROM directory_people WHERE id=?1)",id,err,n)&&statement(s,"DELETE FROM outbox WHERE status IN('pending','failed') AND recipient_email COLLATE NOCASE IN(SELECT email FROM directory_people WHERE id=?1)",id,err,n)&&statement(s,"DELETE FROM directory_people WHERE id=?1",id,err,n)&&materialize(s,err,n);
    return finish(s,ok,outer,err,n);
}
int workspace_remove_group(Store *s,int64_t id,char *err,size_t n) {
    if(!exists(s,"directory_groups",id)){snprintf(err,n,"Gruppo non trovato.");return 0;}
    int outer=sqlite3_get_autocommit(s->db);
    if(!store_exec(s,"SAVEPOINT workspace",err,n))return 0;
    int ok=statement(s,"DELETE FROM directory_groups WHERE id=?1",id,err,n)&&materialize(s,err,n);
    return finish(s,ok,outer,err,n);
}
int workspace_assign(Store *s,int64_t id,const char *role,const int64_t *people,size_t pc,const int64_t *groups,size_t gc,char *err,size_t n) {
    if(!role||(strcmp(role,"business")&&strcmp(role,"technical"))||pc>1000||gc>1000||!exists(s,"certificates",id)){snprintf(err,n,"Assegnazione non valida.");return 0;}
    int outer=sqlite3_get_autocommit(s->db);
    if(!store_exec(s,"SAVEPOINT workspace",err,n))return 0;
    sqlite3_stmt *q=NULL;int ok=1;
    for(int type=0;type<2&&ok;type++){
        const char *sql=type?"INSERT OR IGNORE INTO certificate_groups(certificate_id,role,group_id) VALUES(?1,?2,?3)":"INSERT OR IGNORE INTO directory_assignments(certificate_id,role,person_id,group_id) VALUES(?1,?2,?3,0)";
        const int64_t *ids=type?groups:people;size_t count=type?gc:pc;
        ok=sqlite3_prepare_v2(s->db,sql,-1,&q,NULL)==SQLITE_OK;
        for(size_t i=0;i<count&&ok;i++){
            if(!exists(s,type?"directory_groups":"directory_people",ids[i])){snprintf(err,n,"Persona o gruppo non trovato.");ok=0;break;}
            sqlite3_reset(q);sqlite3_clear_bindings(q);
            ok=sqlite3_bind_int64(q,1,id)==SQLITE_OK&&sqlite3_bind_text(q,2,role,-1,SQLITE_TRANSIENT)==SQLITE_OK&&sqlite3_bind_int64(q,3,ids[i])==SQLITE_OK&&sqlite3_step(q)==SQLITE_DONE;
            if(!ok)failure(s,err,n);
        }
        sqlite3_finalize(q);q=NULL;
    }
    if(ok) ok=materialize(s,err,n);
    return finish(s,ok,outer,err,n);
}
int workspace_save_policy(Store *s,int64_t id,const char *thresholds,int enabled,const char *email,const char *name,int days,char *err,size_t n){
    if(!thresholds||strlen(thresholds)>200||!text_valid(name,120)||(*email&&!store_email_valid(email))||days<0||days>365||(enabled!=0&&enabled!=1)||!exists(s,"certificates",id)){snprintf(err,n,"Regola promemoria non valida.");return 0;}
    char *copy=strdup(thresholds);if(!copy)return 0;char *write=copy;for(const char *read=copy;*read;read++)if(!isspace((unsigned char)*read))*write++=*read;*write=0;int values[64],count=0,zero=0,ok=1;char *cursor=copy;
    while(*cursor&&ok){char *end;long value=strtol(cursor,&end,10);if(!isdigit((unsigned char)*cursor)||end==cursor||value<0||value>3650||(*end&&*end!=',')||count==64){ok=0;break;}for(int i=0;i<count;i++)if(values[i]==value)ok=0;values[count++]=(int)value;if(!value)zero=1;cursor=*end?end+1:end;if(*end&&! *cursor)ok=0;}
    free(copy);if(!ok||!count||!zero){snprintf(err,n,"Soglie: numeri distinti tra 0 e 3650, separati da virgola; includi 0.");return 0;}
    for(int i=0;i<count;i++)for(int j=i+1;j<count;j++)if(values[j]>values[i]){int v=values[i];values[i]=values[j];values[j]=v;}
    char canonical[256]="";size_t pos=0;for(int i=0;i<count;i++)pos+=(size_t)snprintf(canonical+pos,sizeof canonical-pos,"%s%d",i?",":"",values[i]);
    int outer=sqlite3_get_autocommit(s->db);
    if(!store_exec(s,"SAVEPOINT workspace",err,n))return 0;
    sqlite3_stmt *q=NULL;ok=sqlite3_prepare_v2(s->db,"INSERT INTO reminder_policies(certificate_id,thresholds,enabled,escalation_email,escalation_name,escalation_after_days) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(certificate_id) DO UPDATE SET thresholds=excluded.thresholds,enabled=excluded.enabled,escalation_email=excluded.escalation_email,escalation_name=excluded.escalation_name,escalation_after_days=excluded.escalation_after_days",-1,&q,NULL)==SQLITE_OK&&sqlite3_bind_int64(q,1,id)==SQLITE_OK&&sqlite3_bind_text(q,2,canonical,-1,SQLITE_TRANSIENT)==SQLITE_OK&&sqlite3_bind_int(q,3,enabled)==SQLITE_OK&&sqlite3_bind_text(q,4,email,-1,SQLITE_TRANSIENT)==SQLITE_OK&&sqlite3_bind_text(q,5,name,-1,SQLITE_TRANSIENT)==SQLITE_OK&&sqlite3_bind_int(q,6,days)==SQLITE_OK&&sqlite3_step(q)==SQLITE_DONE;
    if(!ok) failure(s,err,n);
    sqlite3_finalize(q);return finish(s,ok,outer,err,n);
}
int workspace_monitor_mail(Store *s,int64_t id,int enabled,const char *recipients,char *err,size_t n){
    if(!recipients||strlen(recipients)>16000||(enabled!=0&&enabled!=1)){snprintf(err,n,"Destinatari monitor non validi.");return 0;}
    char *copy=strdup(recipients);if(!copy)return 0;char *addresses[100];size_t count=0;int ok=1;char *save=NULL;
    for(char *p=strtok_r(copy,";,\r\n",&save);p;p=strtok_r(NULL,";,\r\n",&save)){while(isspace((unsigned char)*p))p++;char *end=p+strlen(p);while(end>p&&isspace((unsigned char)end[-1]))*--end=0;if(!*p)continue;if(count==100||!store_email_valid(p)){ok=0;break;}addresses[count++]=p;}
    if(enabled&&!count)ok=0;
    if(!ok){free(copy);snprintf(err,n,"Inserisci almeno un indirizzo email valido per gli avvisi del monitor.");return 0;}
    int outer=sqlite3_get_autocommit(s->db);
    if(!store_exec(s,"SAVEPOINT workspace",err,n)){free(copy);return 0;}
    sqlite3_stmt *q=NULL;ok=sqlite3_prepare_v2(s->db,"UPDATE monitors SET email_alerts=?1 WHERE id=?2",-1,&q,NULL)==SQLITE_OK&&sqlite3_bind_int(q,1,enabled)==SQLITE_OK&&sqlite3_bind_int64(q,2,id)==SQLITE_OK&&sqlite3_step(q)==SQLITE_DONE;
    if(!ok) failure(s,err,n);
    sqlite3_finalize(q);q=NULL;
    if(ok)ok=statement(s,"DELETE FROM monitor_recipients WHERE monitor_id=?1",id,err,n);
    if(ok)ok=sqlite3_prepare_v2(s->db,"INSERT OR IGNORE INTO monitor_recipients(monitor_id,name,email) VALUES(?1,'',?2)",-1,&q,NULL)==SQLITE_OK;
    for(size_t i=0;i<count&&ok;i++){sqlite3_reset(q);sqlite3_clear_bindings(q);ok=sqlite3_bind_int64(q,1,id)==SQLITE_OK&&sqlite3_bind_text(q,2,addresses[i],-1,SQLITE_TRANSIENT)==SQLITE_OK&&sqlite3_step(q)==SQLITE_DONE;}
    if(!ok) failure(s,err,n);
    sqlite3_finalize(q);free(copy);return finish(s,ok,outer,err,n);
}
static int emit_rows(Store *s,FILE *out,const char *sql,char *err,size_t n){
    sqlite3_stmt *q=NULL;if(sqlite3_prepare_v2(s->db,sql,-1,&q,NULL)!=SQLITE_OK)return failure(s,err,n);fputc('[',out);int first=1,rc;
    while((rc=sqlite3_step(q))==SQLITE_ROW){if(!first)fputc(',',out);first=0;fputc('{',out);for(int i=0;i<sqlite3_column_count(q);i++){if(i)fputc(',',out);const char *name=sqlite3_column_name(q,i);app_json_string(out,name);fputc(':',out);int type=sqlite3_column_type(q,i);if(type==SQLITE_NULL)fputs("null",out);else if(type==SQLITE_INTEGER)fprintf(out,"%"PRId64,(int64_t)sqlite3_column_int64(q,i));else if(!strcmp(name,"group_ids")||!strcmp(name,"member_ids"))fputs((const char *)sqlite3_column_text(q,i),out);else app_json_string(out,(const char *)sqlite3_column_text(q,i));}fputc('}',out);}fputc(']',out);sqlite3_finalize(q);if(rc!=SQLITE_DONE)return failure(s,err,n);return 1;
}
int workspace_state_append(Store *s,FILE *out,char *err,size_t n){
    fputs(",\"people\":",out);if(!emit_rows(s,out,"SELECT p.*,'['||coalesce((SELECT group_concat(group_id) FROM directory_memberships WHERE person_id=p.id),'')||']' AS group_ids FROM directory_people p ORDER BY p.name,p.email",err,n))return 0;
    fputs(",\"groups\":",out);if(!emit_rows(s,out,"SELECT g.*,'['||coalesce((SELECT group_concat(person_id) FROM directory_memberships WHERE group_id=g.id),'')||']' AS member_ids FROM directory_groups g ORDER BY g.name",err,n))return 0;
    fputs(",\"reminder_policies\":",out);if(!emit_rows(s,out,"SELECT * FROM reminder_policies ORDER BY certificate_id",err,n))return 0;
    fputs(",\"monitor_mail\":",out);return emit_rows(s,out,"SELECT monitor_id,name,email FROM monitor_recipients ORDER BY monitor_id,email",err,n);
}
char *workspace_import_preview(Store *s,const char *path,const char *source,size_t *length,char *err,size_t n){
    Store temp={0};CertificateList list={0};char *result=NULL;FILE *out=NULL;int ok=certificate_load_file(path,&list,err,n)&&store_open(&temp,":memory:",err,n);
    if(ok){sqlite3_backup *backup=sqlite3_backup_init(temp.db,"main",s->db,"main");ok=backup&&sqlite3_backup_step(backup,-1)==SQLITE_DONE;if(backup)sqlite3_backup_finish(backup);if(!ok)failure(s,err,n);}
    int64_t *ids=calloc(list.count?list.count:1,sizeof *ids);
    if(!ids)ok=0;
    for(size_t i=0;i<list.count&&ok;i++){int inserted;ok=store_add(&temp,&list.items[i],source,(int64_t)time(NULL),&ids[i],&inserted,err,n);}
    if(ok){out=open_memstream(&result,length);if(!out)ok=0;}
    if(ok)fputs("{\"certificates\":[",out);
    for(size_t i=0;i<list.count&&ok;i++){
        Certificate *c=&list.items[i];CertificateChain chain={0};ok=chain_describe(&temp,ids[i],&chain,err,n);if(!ok)break;
        if(i) fputc(',',out);
        fprintf(out,"{\"id\":%"PRId64",\"not_before\":%"PRId64",\"not_after\":%"PRId64",\"is_ca\":%d,\"common_name\":",ids[i],c->not_before,c->not_after,c->is_ca);app_json_string(out,c->common_name);
        fputs(",\"fingerprint\":",out);app_json_string(out,c->fingerprint);fputs(",\"sans\":",out);app_json_string(out,c->sans);fputs(",\"issuer\":",out);app_json_string(out,c->issuer);fputs(",\"root_ca\":",out);app_json_string(out,chain.root_ca);fputs(",\"intermediate_ca\":",out);app_json_string(out,chain.intermediate_ca);fputs(",\"chain_status\":",out);app_json_string(out,chain.status);fprintf(out,",\"chain_complete\":%s",chain.status&&!strcmp(chain.status,"complete")?"true":"false");chain_free(&chain);
        sqlite3_stmt *q=NULL;int64_t duplicate=0;
        ok=sqlite3_prepare_v2(s->db,"SELECT id FROM certificates WHERE fingerprint=?1",-1,&q,NULL)==SQLITE_OK&&sqlite3_bind_text(q,1,c->fingerprint,-1,SQLITE_TRANSIENT)==SQLITE_OK;
        if(ok){int rc=sqlite3_step(q);if(rc==SQLITE_ROW)duplicate=sqlite3_column_int64(q,0);else if(rc!=SQLITE_DONE)ok=0;}
        if(!ok) failure(s,err,n);
        sqlite3_finalize(q);q=NULL;if(!ok)break;
        fprintf(out,",\"duplicate_id\":%"PRId64",\"renewal_candidates\":[",duplicate);int first=1;
        if(!duplicate&&!c->is_ca){
            if(sqlite3_prepare_v2(s->db,"SELECT id,common_name,not_after FROM certificates WHERE archived=0 AND is_ca=0 ORDER BY not_after DESC,id",-1,&q,NULL)!=SQLITE_OK)ok=failure(s,err,n);
            else{int rc;while((rc=sqlite3_step(q))==SQLITE_ROW){int matches=0;if(!lifecycle_is_candidate(&temp,sqlite3_column_int64(q,0),ids[i],&matches,err,n)){ok=0;break;}if(matches){if(!first)fputc(',',out);first=0;fprintf(out,"{\"id\":%"PRId64",\"not_after\":%"PRId64",\"common_name\":",(int64_t)sqlite3_column_int64(q,0),(int64_t)sqlite3_column_int64(q,2));app_json_string(out,(const char *)sqlite3_column_text(q,1));fputc('}',out);}}if(rc!=SQLITE_DONE&&ok)ok=failure(s,err,n);}
        }
        sqlite3_finalize(q);fputs("]}",out);
    }
    if(out){fputs("]}",out);if(ferror(out))ok=0;if(fclose(out))ok=0;}free(ids);certificate_list_free(&list);store_close(&temp);if(!ok){free(result);return NULL;}return result;
}
