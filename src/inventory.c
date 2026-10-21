#define _POSIX_C_SOURCE 200809L
#include "inventory.h"
#include "workflow_support.h"
#include "remote.h"
#include "remote_service.h"
#include "monitor.h"
#include "app.h"
#include "chain.h"
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* A batch owns immutable input and reviewed outcomes. A worker never sends mail.
 * Each row is committed in one savepoint, including its idempotency receipt. */
typedef struct { const char *role,*name,*email; int64_t person; char *old_name; int action, affected; } Contact;
typedef struct {
    WFForm form; Contact contacts[100]; size_t count;
    char *target; const char *expected,*policy;
} Input;
typedef struct {
    int64_t certificate_id,monitor_id; int archived,conflicts,added,kept;
    char *json; size_t length; char review[65], keep_token[65], update_token[65];
    CertificateChain chain;
} Plan;
static struct { pid_t pid; int64_t deadline,id; Store *owner; char lease[33]; } worker;
static void encoded(FILE *,const char *);
static void field(FILE *,const char *,const char *);


static int fail(char *err,size_t n,const char *text){if(err&&n)snprintf(err,n,"%s",text);return 0;}
static int dbfail(Store *s,char *err,size_t n){return fail(err,n,sqlite3_errmsg(s->db));}
static int text(sqlite3_stmt *q,int i,const char *v){return sqlite3_bind_text(q,i,v?v:"",-1,SQLITE_TRANSIENT)==SQLITE_OK;}
static int prepare(Store *s,sqlite3_stmt **q,const char *sql,char *err,size_t n){return sqlite3_prepare_v2(s->db,sql,-1,q,NULL)==SQLITE_OK?1:dbfail(s,err,n);}
static void hash(const void *data,size_t length,char out[65]){
    unsigned char value[EVP_MAX_MD_SIZE];unsigned int n=0;
    EVP_Digest(data,length,value,&n,EVP_sha256(),NULL);
    for(unsigned int i=0;i<n;i++)snprintf(out+i*2,3,"%02x",value[i]);
}
static void rollback(Store *s,const char *name,int outer){
    /* RELEASE of a top-level savepoint is a commit and may fail SQLITE_BUSY.
     * A full rollback then releases its PENDING lock even with live readers. */
    if(outer)sqlite3_exec(s->db,"ROLLBACK",NULL,NULL,NULL);
    else{char sql[160];snprintf(sql,sizeof sql,"ROLLBACK TO %s; RELEASE %s",name,name);sqlite3_exec(s->db,sql,NULL,NULL,NULL);}
}
static int printable(const char *v,size_t max){if(!v||strlen(v)>max)return 0;for(const unsigned char *p=(const unsigned char *)v;*p;p++)if(*p<32||*p==127)return 0;return 1;}
static void input_free(Input *in){for(size_t i=0;i<in->count;i++)free(in->contacts[i].old_name);free(in->target);wf_form_free(&in->form);memset(in,0,sizeof *in);}
static int input_parse(const unsigned char *body,size_t length,Input *in,char *err,size_t n){
    memset(in,0,sizeof *in);
    if(!wf_form_parse(body,length,&in->form,err,n))return 0;
    const char *target=wf_get(&in->form,"target");
    if(!target||!remote_normalize_target(target,&in->target,err,n))goto bad;
    in->expected=wf_get(&in->form,"expected_fingerprint");in->policy=wf_get(&in->form,"name_policy");
    if(in->policy&&strcmp(in->policy,"keep")&&strcmp(in->policy,"update")){fail(err,n,"Scegli esplicitamente se mantenere o aggiornare i nomi in conflitto.");goto bad;}
    size_t count=wf_count(&in->form,"role");
    if(count>100||count!=wf_count(&in->form,"name")||count!=wf_count(&in->form,"email")){fail(err,n,"Elenco referenti non valido (massimo 100).");goto bad;}
    for(size_t i=0;i<count;i++){
        Contact *c=&in->contacts[i];c->role=wf_nth(&in->form,"role",i);c->name=wf_nth(&in->form,"name",i);c->email=wf_nth(&in->form,"email",i);in->count++;
        if((strcmp(c->role,"business")&&strcmp(c->role,"technical"))||!printable(c->name,120)||!store_email_valid(c->email)){fail(err,n,"Referente non valido: ruolo, nome o email.");goto bad;}
        for(size_t j=0;j<i;j++)if(!strcasecmp(c->email,in->contacts[j].email)){
            if(!strcmp(c->role,in->contacts[j].role)){fail(err,n,"Email duplicata per lo stesso ruolo.");goto bad;}
            if(strcmp(c->name,in->contacts[j].name)){fail(err,n,"La stessa persona non può avere nomi diversi nei due ruoli.");goto bad;}
        }
    }
    return 1;
bad:input_free(in);return 0;
}
static int fetch(Input *in,RemoteResult *r,char *err,size_t n){
    const char *token=wf_get(&in->form,"token");
    if(token&&*token){const char *source=remote_snapshot_target(token);if(!source||strcmp(source,in->target))return fail(err,n,"Verifica URL scaduta o riferita a un altro servizio: ripeti il controllo.");}
    if(!remote_fetch(in->target,r,err,n))return 0;
    if(!r->verified||!r->certificates.count||r->certificates.items[0].is_ca){fail(err,n,r->verification_error&&*r->verification_error?r->verification_error:"Il servizio non presenta un certificato TLS verificato.");return 0;}
    if(in->expected&&*in->expected&&strcmp(in->expected,r->certificates.items[0].fingerprint))return fail(err,n,"Il certificato online è cambiato: rivedi il piano prima di importare.");
    return 1;
}
static void plan_free(Plan *p){free(p->json);chain_free(&p->chain);memset(p,0,sizeof *p);}
static int describe_presented(Store *s,const RemoteResult *r,CertificateChain *chain,char *err,size_t n){
    Store temp={0};int ok=sqlite3_open(":memory:",&temp.db)==SQLITE_OK;
    if(!ok){if(temp.db)dbfail(&temp,err,n);else fail(err,n,"Memoria insufficiente.");store_close(&temp);return 0;}
    /* The server normally omits its root. Reconstruct the presented leaf using
     * the registered CA certificates in a private in-memory copy. Both normal
     * certificate writes and their audit triggers affect only this copy. */
    sqlite3_backup *backup=sqlite3_backup_init(temp.db,"main",s->db,"main");
    if(backup){int rc=sqlite3_backup_step(backup,-1);int finished=sqlite3_backup_finish(backup);ok=rc==SQLITE_DONE&&finished==SQLITE_OK;}
    else ok=0;
    if(!ok){dbfail(&temp,err,n);store_close(&temp);return 0;}
    int64_t leaf=0;
    for(size_t i=0;i<r->certificates.count&&ok;i++){int64_t id=0;int inserted=0;ok=store_add(&temp,&r->certificates.items[i],r->target,r->checked_at,&id,&inserted,err,n);if(!i)leaf=id;}
    if(ok)ok=chain_describe(&temp,leaf,chain,err,n);
    store_close(&temp);return ok;
}
static int make_plan(Store *s,Input *in,const RemoteResult *r,Plan *p,char *err,size_t n){
    memset(p,0,sizeof *p);sqlite3_stmt *q=NULL;int rc;
    if(!prepare(s,&q,"SELECT id,archived FROM certificates WHERE fingerprint=?1",err,n))return 0;
    text(q,1,r->certificates.items[0].fingerprint);rc=sqlite3_step(q);
    if(rc==SQLITE_ROW){p->certificate_id=sqlite3_column_int64(q,0);p->archived=sqlite3_column_int(q,1);}else if(rc!=SQLITE_DONE){sqlite3_finalize(q);return dbfail(s,err,n);}sqlite3_finalize(q);q=NULL;
    if(p->archived)return fail(err,n,"Il certificato è archiviato: risolvi prima il conflitto nel registro.");
    if(!prepare(s,&q,"SELECT id FROM monitors WHERE certificate_id=?1 AND target=?2",err,n))return 0;
    sqlite3_bind_int64(q,1,p->certificate_id);text(q,2,in->target);rc=sqlite3_step(q);if(rc==SQLITE_ROW)p->monitor_id=sqlite3_column_int64(q,0);else if(rc!=SQLITE_DONE){sqlite3_finalize(q);return dbfail(s,err,n);}sqlite3_finalize(q);q=NULL;
    int contacts_count=0;
    if(!prepare(s,&q,"SELECT count(*) FROM contacts WHERE certificate_id=?1",err,n))return 0;sqlite3_bind_int64(q,1,p->certificate_id);if(sqlite3_step(q)==SQLITE_ROW)contacts_count=sqlite3_column_int(q,0);else{sqlite3_finalize(q);return dbfail(s,err,n);}sqlite3_finalize(q);q=NULL;
    for(size_t i=0;i<in->count;i++){
        Contact *c=&in->contacts[i];free(c->old_name);c->old_name=NULL;c->person=0;c->affected=0;c->action=0;
        if(!prepare(s,&q,"SELECT p.id,p.name,(SELECT count(DISTINCT certificate_id) FROM directory_assignments WHERE person_id=p.id) FROM directory_people p WHERE p.email=?1 COLLATE NOCASE",err,n))return 0;
        text(q,1,c->email);rc=sqlite3_step(q);
        if(rc==SQLITE_ROW){c->person=sqlite3_column_int64(q,0);c->old_name=strdup((const char *)sqlite3_column_text(q,1));c->affected=sqlite3_column_int(q,2);if(!c->old_name){sqlite3_finalize(q);return fail(err,n,"Memoria insufficiente.");}}
        else if(rc!=SQLITE_DONE){sqlite3_finalize(q);return dbfail(s,err,n);}sqlite3_finalize(q);q=NULL;
        int assigned=0;if(!prepare(s,&q,"SELECT 1 FROM contacts WHERE certificate_id=?1 AND role=?2 AND email=?3 COLLATE NOCASE",err,n))return 0;
        sqlite3_bind_int64(q,1,p->certificate_id);text(q,2,c->role);text(q,3,c->email);rc=sqlite3_step(q);if(rc==SQLITE_ROW)assigned=1;else if(rc!=SQLITE_DONE){sqlite3_finalize(q);return dbfail(s,err,n);}sqlite3_finalize(q);q=NULL;
        c->action=c->old_name&&*c->name&&strcmp(c->old_name,c->name)?2:assigned?1:0;
        if(!assigned)contacts_count++;
        if(c->action==2)p->conflicts++;else if(c->action==1)p->kept++;else p->added++;
    }
    if(contacts_count>100)return fail(err,n,"Il salvataggio supererebbe il limite di 100 referenti per certificato.");
    if(!describe_presented(s,r,&p->chain,err,n))return 0;
    FILE *out=open_memstream(&p->json,&p->length);if(!out)return fail(err,n,"Memoria insufficiente.");
    fputs("{\"target\":",out);app_json_string(out,in->target);fputs(",\"certificate\":{\"fingerprint\":",out);app_json_string(out,r->certificates.items[0].fingerprint);
    fprintf(out,",\"id\":%"PRId64",\"new\":%s,\"common_name\":",p->certificate_id,p->certificate_id?"false":"true");app_json_string(out,r->certificates.items[0].common_name);
    fputs(",\"issuer\":",out);app_json_string(out,r->certificates.items[0].issuer);
    fputs(",\"intermediate_ca\":",out);app_json_string(out,p->chain.intermediate_ca);
    fputs(",\"root_ca\":",out);app_json_string(out,p->chain.root_ca);
    fputs(",\"chain_status\":",out);app_json_string(out,p->chain.status);
    fprintf(out,",\"chain_complete\":%s",p->chain.status&&!strcmp(p->chain.status,"complete")?"true":"false");
    fprintf(out,",\"not_before\":%"PRId64",\"not_after\":%"PRId64"},\"monitor\":{\"id\":%"PRId64",\"created\":%s},\"contacts\":[",r->certificates.items[0].not_before,r->certificates.items[0].not_after,p->monitor_id,p->monitor_id?"false":"true");
    for(size_t i=0;i<in->count;i++){
        Contact *c=&in->contacts[i];if(i)fputc(',',out);fputs("{\"role\":",out);app_json_string(out,c->role);fputs(",\"email\":",out);app_json_string(out,c->email);fputs(",\"name\":",out);app_json_string(out,c->name);fputs(",\"existing_name\":",out);app_json_string(out,c->old_name?c->old_name:"");fputs(",\"action\":",out);app_json_string(out,c->action==2?"conflict":c->action==1?"kept":"added");fprintf(out,",\"person_id\":%"PRId64",\"affected_certificates\":%d}",c->person,c->affected);
    }
    fprintf(out,"],\"conflicts\":%d,\"added\":%d,\"kept\":%d,\"preserved_contacts\":%d",p->conflicts,p->added,p->kept,contacts_count-(int)in->count);
    /* Machine-readable review state uses the existing strict form decoder.
     * Percent encoding makes its JSON string ASCII with no quotes or escapes. */
    char *state=NULL;size_t state_size=0;FILE *state_out=open_memstream(&state,&state_size);
    if(!state_out){fclose(out);plan_free(p);return fail(err,n,"Memoria insufficiente.");}
    fprintf(state_out,"certificate_id=%"PRId64"&monitor_id=%"PRId64,p->certificate_id,p->monitor_id);
    for(size_t i=0;i<in->count;i++){Contact *c=&in->contacts[i];char person[32];snprintf(person,sizeof person,"%"PRId64,c->person);field(state_out,"role",c->role);field(state_out,"email",c->email);field(state_out,"incoming",c->name);field(state_out,"existing",c->old_name?c->old_name:"");field(state_out,"person_id",person);}
    int state_ok=!ferror(state_out);if(fclose(state_out))state_ok=0;
    if(!state_ok){free(state);fclose(out);plan_free(p);return fail(err,n,"Memoria insufficiente.");}
    fputs(",\"review_state\":",out);app_json_string(out,state);free(state);fputc('}',out);
    int ok=!ferror(out);if(fclose(out))ok=0;if(!ok){plan_free(p);return fail(err,n,"Impossibile preparare il piano.");}hash(p->json,p->length,p->review);
    /* Batch siblings may have added precisely the person/certificate reviewed
     * here. These signatures allow that safe additive rebase, while a changed
     * effective shared name still requires a new review. */
    for(int update=0;update<2;update++){
        char *buffer=NULL;size_t size=0;out=open_memstream(&buffer,&size);if(!out){plan_free(p);return fail(err,n,"Memoria insufficiente.");}
        app_json_string(out,in->target);app_json_string(out,r->certificates.items[0].fingerprint);
        for(size_t i=0;i<in->count;i++){Contact *c=&in->contacts[i];app_json_string(out,c->role);app_json_string(out,c->email);app_json_string(out,update&&*c->name?c->name:c->old_name?c->old_name:c->name);if(update)app_json_string(out,c->action==2?c->old_name:"");}
        fclose(out);hash(buffer,size,update?p->update_token:p->keep_token);free(buffer);
    }
    return 1;
}
static char *plan_json(Plan *p,size_t *length){char *json=NULL;FILE *out=open_memstream(&json,length);if(!out)return NULL;fputs("{\"ok\":true,\"review_token\":",out);app_json_string(out,p->review);fputs(",\"plan\":",out);fputs(p->json,out);fputs("}",out);if(fclose(out)){free(json);return NULL;}return json;}
static int apply_row(Store *s,Input *in,const RemoteResult *r,Plan *p,int64_t now,int64_t *saved,char *err,size_t n){
    if(p->conflicts&&(!in->policy||!*in->policy))return fail(err,n,"Ci sono nomi in conflitto: scegli esplicitamente mantieni o aggiorna.");
    int64_t id=0;int inserted=0;
    for(size_t i=0;i<r->certificates.count;i++){
        int64_t current=0;if(!store_add(s,&r->certificates.items[i],in->target,now,&current,&inserted,err,n))return 0;if(!i)id=current;
    }
    sqlite3_stmt *q=NULL;
    for(size_t i=0;i<in->count;i++){
        Contact *c=&in->contacts[i];
        if(!prepare(s,&q,"INSERT OR IGNORE INTO directory_people(name,email) VALUES(?1,?2)",err,n))return 0;text(q,1,c->name);text(q,2,c->email);int ok=sqlite3_step(q)==SQLITE_DONE;sqlite3_finalize(q);q=NULL;if(!ok)return dbfail(s,err,n);
        if(c->action==2&&in->policy&&!strcmp(in->policy,"update")){
            if(!prepare(s,&q,"UPDATE directory_people SET name=?1 WHERE email=?2 COLLATE NOCASE",err,n))return 0;text(q,1,c->name);text(q,2,c->email);ok=sqlite3_step(q)==SQLITE_DONE;sqlite3_finalize(q);q=NULL;if(!ok)return dbfail(s,err,n);
            if(!prepare(s,&q,"UPDATE contacts SET name=?1 WHERE email=?2 COLLATE NOCASE",err,n))return 0;text(q,1,c->name);text(q,2,c->email);ok=sqlite3_step(q)==SQLITE_DONE;sqlite3_finalize(q);q=NULL;if(!ok)return dbfail(s,err,n);
        }
        if(!prepare(s,&q,"INSERT OR IGNORE INTO directory_assignments(certificate_id,role,person_id,group_id) SELECT ?1,?2,id,0 FROM directory_people WHERE email=?3 COLLATE NOCASE",err,n))return 0;sqlite3_bind_int64(q,1,id);text(q,2,c->role);text(q,3,c->email);ok=sqlite3_step(q)==SQLITE_DONE;sqlite3_finalize(q);q=NULL;if(!ok)return dbfail(s,err,n);
        if(!prepare(s,&q,"INSERT INTO contacts(certificate_id,role,name,email) SELECT ?1,?2,name,email FROM directory_people WHERE email=?3 COLLATE NOCASE ON CONFLICT(certificate_id,role,email) DO UPDATE SET name=excluded.name",err,n))return 0;sqlite3_bind_int64(q,1,id);text(q,2,c->role);text(q,3,c->email);ok=sqlite3_step(q)==SQLITE_DONE;sqlite3_finalize(q);q=NULL;if(!ok)return dbfail(s,err,n);
    }
    if(!p->monitor_id){int64_t mid;if(!monitor_save(s,0,id,in->target,900,1,now,&mid,err,n))return 0;}
    if(!wf_audit(s,"certificate",id,"inventory_row",in->target,err,n))return 0;
    *saved=id;return 1;
}

/* This signature deliberately includes the policy. Reusing a key with changed
 * input must be rejected even after the first request succeeded. */
static void input_hash(Input *in,const char *fingerprint,char digest[65]){
    char *buffer=NULL;size_t size=0;FILE *out=open_memstream(&buffer,&size);if(!out){digest[0]=0;return;}
    app_json_string(out,in->target);app_json_string(out,fingerprint);app_json_string(out,in->policy?in->policy:"");
    for(size_t i=0;i<in->count;i++){app_json_string(out,in->contacts[i].role);app_json_string(out,in->contacts[i].name);app_json_string(out,in->contacts[i].email);}fclose(out);hash(buffer,size,digest);free(buffer);
}
static int receipt(Store *s,const char *key,const char *digest,int64_t *id,char *err,size_t n){
    sqlite3_stmt *q=NULL;if(!prepare(s,&q,"SELECT payload_hash,certificate_id FROM inventory_commits WHERE idempotency_key=?1",err,n))return -1;text(q,1,key);int rc=sqlite3_step(q),result=0;
    if(rc==SQLITE_ROW){if(strcmp((const char *)sqlite3_column_text(q,0),digest)){fail(err,n,"Chiave di importazione già usata per dati diversi.");result=-1;}else{*id=sqlite3_column_int64(q,1);result=1;}}else if(rc!=SQLITE_DONE){dbfail(s,err,n);result=-1;}sqlite3_finalize(q);return result;
}
static int save_receipt(Store *s,const char *key,const char *digest,int64_t id,char *err,size_t n){
    sqlite3_stmt *q=NULL;if(!prepare(s,&q,"INSERT INTO inventory_commits(idempotency_key,payload_hash,certificate_id,created_at) VALUES(?1,?2,?3,?4)",err,n))return 0;text(q,1,key);text(q,2,digest);sqlite3_bind_int64(q,3,id);sqlite3_bind_int64(q,4,(int64_t)time(NULL));int ok=sqlite3_step(q)==SQLITE_DONE;sqlite3_finalize(q);return ok?1:dbfail(s,err,n);
}
static char *committed_json(int64_t id,int replay,size_t *length){char *json=NULL;FILE *out=open_memstream(&json,length);if(!out)return NULL;fprintf(out,"{\"ok\":true,\"certificate_id\":%"PRId64",\"replayed\":%s}",id,replay?"true":"false");fclose(out);return json;}
static char *single(Store *s,int commit,const unsigned char *body,size_t bodylen,size_t *length,int *status,char *err,size_t n){
    Input in;RemoteResult r={0};Plan p={0};char *json=NULL;int64_t id=0;int savepoint=0,outer=sqlite3_get_autocommit(s->db);char digest[65];
    if(!input_parse(body,bodylen,&in,err,n))return NULL;
    const char *key=wf_get(&in.form,"idempotency_key"),*review=wf_get(&in.form,"review_token");
    if(commit){
        if(!printable(key,160)||!*key||!in.expected||!*in.expected||!review||strlen(review)!=64){fail(err,n,"Per importare servono un piano approvato, l'impronta attesa e una chiave univoca.");goto done;}
        input_hash(&in,in.expected,digest);int found=receipt(s,key,digest,&id,err,n);if(found<0){*status=409;goto done;}if(found){json=committed_json(id,1,length);goto done;}
    }
    if(!fetch(&in,&r,err,n))goto done;
    if(commit){if(!store_exec(s,"SAVEPOINT inventory_row",err,n))goto done;savepoint=1;}
    if(!make_plan(s,&in,&r,&p,err,n))goto done;
    if(!commit){json=plan_json(&p,length);goto done;}
    if(strcmp(review,p.review)){*status=409;fail(err,n,"Il registro è cambiato dopo l'anteprima: aggiorna e approva il nuovo piano.");goto done;}
    int found=receipt(s,key,digest,&id,err,n);if(found<0){*status=409;goto done;}if(found){json=committed_json(id,1,length);goto done;}
    if(!apply_row(s,&in,&r,&p,(int64_t)time(NULL),&id,err,n)||!save_receipt(s,key,digest,id,err,n))goto done;
    if(!store_exec(s,"RELEASE inventory_row",err,n))goto done;savepoint=0;json=committed_json(id,0,length);
done:
    if(savepoint)rollback(s,"inventory_row",outer);
    input_free(&in);remote_result_free(&r);plan_free(&p);if(json)*status=200;return json;
}

const char *inventory_schema(void){return
    "CREATE TABLE inventory_commits(idempotency_key TEXT PRIMARY KEY,payload_hash TEXT NOT NULL,certificate_id INTEGER NOT NULL,created_at INTEGER NOT NULL);"
    "CREATE TABLE inventory_batches(id INTEGER PRIMARY KEY,name TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'draft',name_policy TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);"
    "CREATE TABLE inventory_rows(id INTEGER PRIMARY KEY,batch_id INTEGER NOT NULL REFERENCES inventory_batches(id) ON DELETE CASCADE,position INTEGER NOT NULL,line INTEGER NOT NULL,target TEXT NOT NULL,payload TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',plan_json TEXT NOT NULL DEFAULT '',review_token TEXT NOT NULL DEFAULT '',keep_token TEXT NOT NULL DEFAULT '',update_token TEXT NOT NULL DEFAULT '',fingerprint TEXT NOT NULL DEFAULT '',error TEXT NOT NULL DEFAULT '',certificate_id INTEGER,claim_until INTEGER NOT NULL DEFAULT 0,lease_token TEXT NOT NULL DEFAULT '',UNIQUE(batch_id,position));"
    "CREATE INDEX inventory_rows_work ON inventory_rows(status,claim_until,batch_id,position);";
}
static void encoded(FILE *out,const char *value){for(const unsigned char *p=(const unsigned char *)value;*p;p++){if(isalnum(*p)||*p=='-'||*p=='_'||*p=='.'||*p=='~')fputc(*p,out);else fprintf(out,"%%%02X",*p);}}
static void field(FILE *out,const char *name,const char *value){fputc('&',out);encoded(out,name);fputc('=',out);encoded(out,value?value:"");}
static const char *row_value(const WFForm *f,size_t i,const char *suffix){char key[128];snprintf(key,sizeof key,"row_%zu_%s",i,suffix);return wf_get(f,key);}
/* Pipe lists preserve empty slots so names cannot slide onto a different email. */
static int list_contacts(FILE *out,const char *role,const char *names,const char *emails,char *err,size_t n){
    if(!emails||!*emails)return (!names||!*names)?1:fail(err,n,"Nome senza email nella riga CSV.");
    char *e=strdup(emails),*a=strdup(names?names:"");if(!e||!a){free(e);free(a);return fail(err,n,"Memoria insufficiente.");}char *ep=e,*np=a;int ok=1;
    while(ep){char *next_e=strchr(ep,'|'),*next_n=np?strchr(np,'|'):NULL;if(next_e)*next_e++=0;if(next_n)*next_n++=0;
        while(*ep&&isspace((unsigned char)*ep))ep++;char *end=ep+strlen(ep);while(end>ep&&isspace((unsigned char)end[-1]))*--end=0;
        char *name=np?np:"";while(*name&&isspace((unsigned char)*name))name++;end=name+strlen(name);while(end>name&&isspace((unsigned char)end[-1]))*--end=0;
        if(!*ep){ok=fail(err,n,"Email vuota nell'elenco dei referenti.");break;}field(out,"role",role);field(out,"name",name);field(out,"email",ep);ep=next_e;np=next_n;
    }
    if(ok&&np)ok=fail(err,n,"Il numero dei nomi supera quello delle email.");free(e);free(a);return ok;
}
static int create_batch(Store *s,const WFForm *f,int64_t *id,char *err,size_t n){
    int64_t rows=0;if(!wf_number(wf_get(f,"rows"),1,100,&rows))return fail(err,n,"Il lotto deve contenere da 1 a 100 righe.");
    const char *name=wf_get(f,"name");if(!name)name="";if(!printable(name,200))return fail(err,n,"Nome lotto non valido.");
    int outer=sqlite3_get_autocommit(s->db);if(!store_exec(s,"SAVEPOINT inventory_batch",err,n))return 0;sqlite3_stmt *q=NULL;int ok=prepare(s,&q,"INSERT INTO inventory_batches(name,created_at,updated_at) VALUES(?1,?2,?2)",err,n);
    if(ok){text(q,1,name);sqlite3_bind_int64(q,2,(int64_t)time(NULL));ok=sqlite3_step(q)==SQLITE_DONE;}sqlite3_finalize(q);q=NULL;if(!ok){dbfail(s,err,n);goto done;}*id=sqlite3_last_insert_rowid(s->db);
    for(size_t i=0;i<(size_t)rows&&ok;i++){
        const char *target=row_value(f,i,"target"),*raw=row_value(f,i,"payload");int64_t line=(int64_t)i+2;const char *line_text=row_value(f,i,"line");if(line_text&&!wf_number(line_text,1,10000000,&line)){ok=fail(err,n,"Numero riga non valido.");break;}
        char *payload=NULL;size_t len=0;
        if(raw){payload=strdup(raw);len=strlen(raw);if(!payload){ok=fail(err,n,"Memoria insufficiente.");break;}}
        else{
            if(!target){ok=fail(err,n,"URL mancante nella riga CSV.");break;}
            FILE *out=open_memstream(&payload,&len);if(!out){ok=fail(err,n,"Memoria insufficiente.");break;}fputs("target=",out);encoded(out,target);
            ok=list_contacts(out,"business",row_value(f,i,"business_name"),row_value(f,i,"business_email"),err,n)&&list_contacts(out,"technical",row_value(f,i,"technical_name"),row_value(f,i,"technical_email"),err,n);fclose(out);
        }
        Input in;if(ok){ok=input_parse((const unsigned char *)payload,len,&in,err,n);if(ok){
            ok=prepare(s,&q,"INSERT INTO inventory_rows(batch_id,position,line,target,payload) VALUES(?1,?2,?3,?4,?5)",err,n);
            if(ok){sqlite3_bind_int64(q,1,*id);sqlite3_bind_int64(q,2,(int64_t)i);sqlite3_bind_int64(q,3,line);text(q,4,in.target);text(q,5,payload);ok=sqlite3_step(q)==SQLITE_DONE;if(!ok)dbfail(s,err,n);}sqlite3_finalize(q);q=NULL;input_free(&in);
        }}free(payload);
    }
done:
    if(ok)ok=store_exec(s,"RELEASE inventory_batch",err,n);if(!ok)rollback(s,"inventory_batch",outer);return ok;
}
static int batch_token(Store *s,int64_t id,char digest[65],char *err,size_t n){
    char *buffer=NULL;size_t length=0;FILE *out=open_memstream(&buffer,&length);if(!out)return fail(err,n,"Memoria insufficiente.");
    int ok=wf_json_rows(s,out,"SELECT id,status,review_token,error FROM inventory_rows WHERE batch_id=?1 ORDER BY position",id,err,n);fclose(out);if(ok)hash(buffer,length,digest);free(buffer);return ok;
}
static char *batch_json(Store *s,int64_t id,size_t *length,int *status,char *err,size_t n){
    char *json=NULL;FILE *out=open_memstream(&json,length);if(!out)return NULL;int ok=1;
    if(!id){fputs("{\"ok\":true,\"batches\":",out);ok=wf_json_rows(s,out,"SELECT b.*,(SELECT count(*) FROM inventory_rows WHERE batch_id=b.id) AS row_count,(SELECT count(*) FROM inventory_rows WHERE batch_id=b.id AND status='imported') AS imported,(SELECT count(*) FROM inventory_rows WHERE batch_id=b.id AND status='ready') AS ready_count,(SELECT count(*) FROM inventory_rows WHERE batch_id=b.id AND status='checking') AS checking_count,(SELECT count(*) FROM inventory_rows WHERE batch_id=b.id AND status IN('error','needs_review')) AS errors FROM inventory_batches b ORDER BY id DESC LIMIT 200",0,err,n);fputc('}',out);}
    else{
        sqlite3_stmt *q=NULL;ok=prepare(s,&q,"SELECT name,status,name_policy,created_at,updated_at FROM inventory_batches WHERE id=?1",err,n);if(ok){sqlite3_bind_int64(q,1,id);if(sqlite3_step(q)!=SQLITE_ROW){*status=404;ok=fail(err,n,"Lotto non trovato.");}}
        if(ok){fprintf(out,"{\"ok\":true,\"id\":%"PRId64",\"name\":",id);app_json_string(out,(const char *)sqlite3_column_text(q,0));fputs(",\"status\":",out);app_json_string(out,(const char *)sqlite3_column_text(q,1));fputs(",\"name_policy\":",out);app_json_string(out,(const char *)sqlite3_column_text(q,2));fprintf(out,",\"created_at\":%"PRId64",\"updated_at\":%"PRId64,(int64_t)sqlite3_column_int64(q,3),(int64_t)sqlite3_column_int64(q,4));}sqlite3_finalize(q);q=NULL;
        if(ok){char token[65];ok=batch_token(s,id,token,err,n);if(ok){fputs(",\"review_token\":",out);app_json_string(out,token);fputs(",\"rows\":[",out);ok=prepare(s,&q,"SELECT id,line,target,status,plan_json,error,certificate_id,payload FROM inventory_rows WHERE batch_id=?1 ORDER BY position",err,n);if(ok){sqlite3_bind_int64(q,1,id);int first=1,rc;while((rc=sqlite3_step(q))==SQLITE_ROW){if(!first)fputc(',',out);first=0;fprintf(out,"{\"id\":%"PRId64",\"line\":%"PRId64",\"target\":",(int64_t)sqlite3_column_int64(q,0),(int64_t)sqlite3_column_int64(q,1));app_json_string(out,(const char *)sqlite3_column_text(q,2));fputs(",\"status\":",out);app_json_string(out,(const char *)sqlite3_column_text(q,3));fputs(",\"plan\":",out);const char *plan=(const char *)sqlite3_column_text(q,4);fputs(plan&&*plan?plan:"null",out);fputs(",\"error\":",out);app_json_string(out,(const char *)sqlite3_column_text(q,5));fprintf(out,",\"certificate_id\":%"PRId64,(int64_t)sqlite3_column_int64(q,6));fputs(",\"payload\":",out);app_json_string(out,(const char *)sqlite3_column_text(q,7));fputc('}',out);}if(rc!=SQLITE_DONE)ok=dbfail(s,err,n);}sqlite3_finalize(q);fputs("]}",out);}}
    }
    if(fclose(out))ok=0;if(!ok){free(json);return NULL;}*status=200;return json;
}

static int batch_status(Store *s,int64_t id,char value[32],char *err,size_t n){
    sqlite3_stmt *q=NULL;if(!prepare(s,&q,"SELECT status FROM inventory_batches WHERE id=?1",err,n))return 0;
    sqlite3_bind_int64(q,1,id);int rc=sqlite3_step(q);if(rc==SQLITE_ROW)snprintf(value,32,"%s",(const char *)sqlite3_column_text(q,0));sqlite3_finalize(q);return rc==SQLITE_ROW?1:fail(err,n,"Lotto non trovato.");
}
static int update_batch(Store *s,int64_t id,const char *status,const char *policy,char *err,size_t n){
    sqlite3_stmt *q=NULL;if(!prepare(s,&q,"UPDATE inventory_batches SET status=?1,name_policy=CASE WHEN ?2='' THEN name_policy ELSE ?2 END,updated_at=?3 WHERE id=?4",err,n))return 0;
    text(q,1,status);text(q,2,policy);sqlite3_bind_int64(q,3,(int64_t)time(NULL));sqlite3_bind_int64(q,4,id);int ok=sqlite3_step(q)==SQLITE_DONE;sqlite3_finalize(q);return ok?1:dbfail(s,err,n);
}
static int row_command(Store *s,int64_t batch,const char *sql,char *err,size_t n){
    sqlite3_stmt *q=NULL;if(!prepare(s,&q,sql,err,n))return 0;sqlite3_bind_int64(q,1,batch);int ok=sqlite3_step(q)==SQLITE_DONE;sqlite3_finalize(q);return ok?1:dbfail(s,err,n);
}
static int batch_action(Store *s,int64_t id,const char *action,const WFForm *f,int *status,char *err,size_t n){
    char state[32];if(!batch_status(s,id,state,err,n)){*status=404;return 0;}
    const char *policy=wf_get(f,"name_policy");if(policy&&strcmp(policy,"keep")&&strcmp(policy,"update"))return fail(err,n,"Scegli mantieni o aggiorna per i nomi condivisi.");
    int outer=sqlite3_get_autocommit(s->db);if(!store_exec(s,"SAVEPOINT inventory_action",err,n))return 0;int ok=0;
    if(!strcmp(action,"pause")){
        ok=row_command(s,id,"UPDATE inventory_rows SET status=CASE WHEN status IN('approved','importing') THEN 'ready' WHEN status='checking' THEN 'pending' ELSE status END,claim_until=0,lease_token='' WHERE batch_id=?1 AND status IN('approved','importing','checking')",err,n)&&update_batch(s,id,"paused",NULL,err,n);
    }else if(!strcmp(action,"plan")){
        if(!strcmp(state,"running")){*status=409;fail(err,n,"Metti in pausa il lotto prima di ripianificarlo.");goto done;}
        ok=row_command(s,id,"UPDATE inventory_rows SET status='pending',error='',claim_until=0,lease_token='' WHERE batch_id=?1 AND status<>'imported'",err,n)&&update_batch(s,id,"planning",policy,err,n);
    }else if(!strcmp(action,"start")){
        if(!strcmp(state,"planning")||!strcmp(state,"draft")||!strcmp(state,"running")){*status=409;fail(err,n,"Attendi il piano prima di approvare l'importazione.");goto done;}
        const char *review=wf_get(f,"review_token");char expected[65];
        if(!review||!batch_token(s,id,expected,err,n)||strcmp(review,expected)){*status=409;fail(err,n,"Il piano del lotto è cambiato: aggiorna il riepilogo prima di approvare.");goto done;}
        size_t selected=wf_count(f,"row_id"),indices=wf_count(f,"row_index");
        if(selected&&indices){fail(err,n,"Usa una sola modalità di selezione delle righe.");goto done;}
        sqlite3_stmt *q=NULL;int64_t ready_count=0;
        if(!prepare(s,&q,"SELECT count(*) FROM inventory_rows WHERE batch_id=?1 AND status IN('ready','approved','importing')",err,n))goto done;sqlite3_bind_int64(q,1,id);if(sqlite3_step(q)==SQLITE_ROW)ready_count=sqlite3_column_int64(q,0);sqlite3_finalize(q);q=NULL;
        if(!ready_count){fail(err,n,"Nessuna riga verificata da importare.");goto done;}
        if(!selected&&!indices){
            if(!prepare(s,&q,"SELECT 1 FROM inventory_rows WHERE batch_id=?1 AND status IN('error','needs_review','pending','checking') LIMIT 1",err,n))goto done;sqlite3_bind_int64(q,1,id);int rc=sqlite3_step(q);sqlite3_finalize(q);q=NULL;
            if(rc==SQLITE_ROW){fail(err,n,"Il lotto contiene errori: seleziona esplicitamente le righe verificate da importare.");goto done;}
            ok=row_command(s,id,"UPDATE inventory_rows SET status='approved',claim_until=0,lease_token='' WHERE batch_id=?1 AND status IN('ready','approved','importing')",err,n);
        }else{
            if(selected+indices>100){fail(err,n,"Troppe righe selezionate.");goto done;}ok=1;
            /* Clear a previous paused selection. A stale worker loses its lease. */
            ok=row_command(s,id,"UPDATE inventory_rows SET status='ready',claim_until=0,lease_token='' WHERE batch_id=?1 AND status IN('approved','importing')",err,n);
            for(size_t i=0;i<selected+indices&&ok;i++){
                int64_t value;if(!wf_number(wf_nth(f,selected?"row_id":"row_index",i),selected?1:0,INT64_MAX,&value)){ok=fail(err,n,"Selezione righe non valida.");break;}
                const char *sql=selected?"UPDATE inventory_rows SET status='approved' WHERE batch_id=?1 AND id=?2 AND status='ready'":"UPDATE inventory_rows SET status='approved' WHERE batch_id=?1 AND position=?2 AND status='ready'";
                ok=prepare(s,&q,sql,err,n);if(ok){sqlite3_bind_int64(q,1,id);sqlite3_bind_int64(q,2,value);ok=sqlite3_step(q)==SQLITE_DONE&&sqlite3_changes(s->db)==1;if(!ok)fail(err,n,"Una riga selezionata non è pronta o non appartiene al lotto.");}sqlite3_finalize(q);q=NULL;
            }
        }
        if(ok){
            /* A conflict must be a deliberate choice, never a hidden default. */
            if(!policy||!*policy){
                ok=prepare(s,&q,"SELECT 1 FROM inventory_rows WHERE batch_id=?1 AND status='approved' AND plan_json LIKE '%\"action\":\"conflict\"%' LIMIT 1",err,n);
                if(ok){sqlite3_bind_int64(q,1,id);if(sqlite3_step(q)==SQLITE_ROW)ok=fail(err,n,"Scegli esplicitamente come risolvere i nomi in conflitto.");}sqlite3_finalize(q);q=NULL;
            }
            if(ok)ok=update_batch(s,id,"running",policy?policy:"keep",err,n)&&wf_audit(s,"inventory",id,"approve",expected,err,n);
        }
    }else fail(err,n,"Azione lotto non valida.");
done:
    if(ok)ok=store_exec(s,"RELEASE inventory_action",err,n);if(!ok)rollback(s,"inventory_action",outer);return ok;
}
char *inventory_api(Store *s,const char *method,const char *path,const unsigned char *body,size_t bodylen,size_t *length,int *status,char *err,size_t n){
    *status=400;*length=0;if(err&&n)*err=0;
    if(!strcmp(method,"POST")&&!strcmp(path,"/api/inventory/plan"))return single(s,0,body,bodylen,length,status,err,n);
    if(!strcmp(method,"POST")&&!strcmp(path,"/api/inventory/commit"))return single(s,1,body,bodylen,length,status,err,n);
    if(!strcmp(path,"/api/inventory/batches")){
        if(!strcmp(method,"GET"))return batch_json(s,0,length,status,err,n);
        if(!strcmp(method,"POST")){WFForm f;if(!wf_form_parse(body,bodylen,&f,err,n))return NULL;int64_t id;int ok=create_batch(s,&f,&id,err,n);wf_form_free(&f);if(ok)return batch_json(s,id,length,status,err,n);return NULL;}
    }
    const char *prefix="/api/inventory/batches/";
    if(!strncmp(path,prefix,strlen(prefix))){const char *rest=path+strlen(prefix),*slash=strchr(rest,'/');char number[32];size_t len=slash?(size_t)(slash-rest):strlen(rest);int64_t id;
        if(!len||len>=sizeof number){fail(err,n,"Lotto non valido.");return NULL;}memcpy(number,rest,len);number[len]=0;if(!wf_number(number,1,INT64_MAX,&id)){fail(err,n,"Lotto non valido.");return NULL;}
        if(!slash&&!strcmp(method,"GET"))return batch_json(s,id,length,status,err,n);
        if(slash&&!strcmp(method,"POST")){WFForm f;if(!wf_form_parse(body,bodylen,&f,err,n))return NULL;int ok=batch_action(s,id,slash+1,&f,status,err,n);wf_form_free(&f);if(ok)return batch_json(s,id,length,status,err,n);return NULL;}
    }
    *status=404;fail(err,n,"Operazione inventario non trovata.");return NULL;
}

static int finish_batch(Store *s,int64_t batch,char *err,size_t n){
    sqlite3_stmt *q=NULL;const char *sql=
        "UPDATE inventory_batches SET status=CASE "
        "WHEN status='planning' THEN 'review' "
        "WHEN EXISTS(SELECT 1 FROM inventory_rows WHERE batch_id=?1 AND status<>'imported') THEN 'review' ELSE 'completed' END,updated_at=?2 "
        "WHERE id=?1 AND status IN('planning','running') AND NOT EXISTS(SELECT 1 FROM inventory_rows WHERE batch_id=?1 AND status IN('pending','checking','approved','importing'))";
    if(!prepare(s,&q,sql,err,n))return 0;sqlite3_bind_int64(q,1,batch);sqlite3_bind_int64(q,2,(int64_t)time(NULL));int ok=sqlite3_step(q)==SQLITE_DONE;sqlite3_finalize(q);return ok?1:dbfail(s,err,n);
}
static int lease_valid(Store *s,int64_t id,const char *lease,const char *operation,char *err,size_t n){
    sqlite3_stmt *q=NULL;if(!prepare(s,&q,"SELECT 1 FROM inventory_rows r JOIN inventory_batches b ON b.id=r.batch_id WHERE r.id=?1 AND r.lease_token=?2 AND b.status=?3",err,n))return 0;
    sqlite3_bind_int64(q,1,id);text(q,2,lease);text(q,3,operation);int ok=sqlite3_step(q)==SQLITE_ROW;sqlite3_finalize(q);if(!ok)fail(err,n,"Il lotto è stato sospeso o la riga è stata ripresa da un altro processo.");return ok;
}
static int record_row(Store *s,int64_t id,const char *lease,const char *state,const Plan *p,const char *fingerprint,int64_t cert,const char *error,char *err,size_t n){
    sqlite3_stmt *q=NULL;
    const char *sql=p?"UPDATE inventory_rows SET status=?1,plan_json=?2,review_token=?3,keep_token=?4,update_token=?5,fingerprint=?6,certificate_id=NULLIF(?7,0),error=?8,claim_until=0,lease_token='' WHERE id=?9 AND lease_token=?10":
        "UPDATE inventory_rows SET status=?1,certificate_id=NULLIF(?7,0),error=?8,claim_until=0,lease_token='' WHERE id=?9 AND lease_token=?10";
    if(!prepare(s,&q,sql,err,n))return 0;text(q,1,state);if(p){text(q,2,p->json);text(q,3,p->review);text(q,4,p->keep_token);text(q,5,p->update_token);text(q,6,fingerprint);}sqlite3_bind_int64(q,7,cert);text(q,8,error);sqlite3_bind_int64(q,9,id);text(q,10,lease);int ok=sqlite3_step(q)==SQLITE_DONE&&sqlite3_changes(s->db)==1;sqlite3_finalize(q);return ok?1:dbfail(s,err,n);
}
static int review_state(const char *plan,WFForm *state,char *err,size_t n){
    memset(state,0,sizeof *state);const char *marker="\"review_state\":\"";
    const char *start=strstr(plan,marker);if(!start)return 0;start+=strlen(marker);const char *end=strchr(start,'"');if(!end)return 0;
    /* This field is our own ASCII percent-encoded protocol, not arbitrary JSON.
     * Reject escapes rather than implementing a second JSON parser. */
    for(const char *p=start;p<end;p++)if((unsigned char)*p<32||(unsigned char)*p>126||*p=='\\')return 0;
    return wf_form_parse((const unsigned char *)start,(size_t)(end-start),state,err,n);
}
static int prior_effect(Store *s,int64_t row,int64_t batch,const char *email,const char *name,int64_t certificate,const char *target,const char *fingerprint,char *err,size_t n){
    sqlite3_stmt *q=NULL;
    if(!prepare(s,&q,"SELECT payload,target,fingerprint,certificate_id FROM inventory_rows WHERE batch_id=?1 AND status='imported' AND position<(SELECT position FROM inventory_rows WHERE id=?2) ORDER BY position",err,n))return 0;
    sqlite3_bind_int64(q,1,batch);sqlite3_bind_int64(q,2,row);int matched=0,rc;
    while((rc=sqlite3_step(q))==SQLITE_ROW){
        if(certificate&&certificate!=sqlite3_column_int64(q,3))continue;
        if(target&&strcmp(target,(const char *)sqlite3_column_text(q,1)))continue;
        if(fingerprint&&strcmp(fingerprint,(const char *)sqlite3_column_text(q,2)))continue;
        if(!email){matched=1;break;}
        const char *payload=(const char *)sqlite3_column_text(q,0);WFForm f;
        if(!wf_form_parse((const unsigned char *)payload,strlen(payload),&f,err,n))continue;
        size_t count=wf_count(&f,"email");
        for(size_t i=0;i<count;i++){const char *e=wf_nth(&f,"email",i),*a=wf_nth(&f,"name",i);if(e&&a&&!strcasecmp(email,e)&&!strcmp(name,a)){matched=1;break;}}
        wf_form_free(&f);if(matched)break;
    }
    if(rc!=SQLITE_ROW&&rc!=SQLITE_DONE)dbfail(s,err,n);sqlite3_finalize(q);return matched;
}
static int sibling_rebase(Store *s,int64_t row,int64_t batch,Input *in,const Plan *p,const char *old_plan,char *err,size_t n){
    WFForm state;if(!review_state(old_plan,&state,err,n))return 0;int ok=0;int64_t certificate=0,monitor=0;
    if(!wf_number(wf_get(&state,"certificate_id"),0,INT64_MAX,&certificate)||!wf_number(wf_get(&state,"monitor_id"),0,INT64_MAX,&monitor))goto done;
    if((certificate&&certificate!=p->certificate_id)||(monitor&&monitor!=p->monitor_id))goto done;
    if(!certificate&&p->certificate_id&&!prior_effect(s,row,batch,NULL,NULL,p->certificate_id,NULL,in->expected,err,n))goto done;
    if(!monitor&&p->monitor_id&&!prior_effect(s,row,batch,NULL,NULL,p->certificate_id,in->target,in->expected,err,n))goto done;
    if(wf_count(&state,"email")!=in->count||wf_count(&state,"role")!=in->count||wf_count(&state,"incoming")!=in->count||wf_count(&state,"existing")!=in->count||wf_count(&state,"person_id")!=in->count)goto done;
    for(size_t i=0;i<in->count;i++){
        Contact *c=&in->contacts[i];const char *email=wf_nth(&state,"email",i),*role=wf_nth(&state,"role",i),*incoming=wf_nth(&state,"incoming",i),*existing=wf_nth(&state,"existing",i);int64_t person=0;
        if(strcmp(email,c->email)||strcmp(role,c->role)||strcmp(incoming,c->name)||!wf_number(wf_nth(&state,"person_id",i),0,INT64_MAX,&person))goto done;
        if(person&&person!=c->person)goto done;
        int changed_name=strcmp(existing,c->old_name?c->old_name:"")!=0;
        int added_person=!person&&c->person;
        if(changed_name||added_person){
            if(!*incoming||!c->old_name||strcmp(c->old_name,incoming))goto done;
            if(changed_name&&person&&(!in->policy||strcmp(in->policy,"update")))goto done;
            if(!prior_effect(s,row,batch,c->email,incoming,0,NULL,NULL,err,n))goto done;
        }
    }
    ok=1;
done:wf_form_free(&state);return ok;
}
static void process_row(const char *db_path,int64_t id,int64_t batch,const char *lease,int commit){
    (void)setpgid(0,0);
    Store s={0};char error[1024]="",local[1024]="";sqlite3_stmt *q=NULL;Input in;memset(&in,0,sizeof in);RemoteResult r={0};Plan p={0};
    char *payload=NULL,*expected=NULL,*old_review=NULL,*old_keep=NULL,*old_update=NULL,*old_plan=NULL,*policy=NULL;int savepoint=0;int64_t cert=0;int ok=0,needs_review=0;
    if(sqlite3_open_v2(db_path,&s.db,SQLITE_OPEN_READWRITE,NULL)!=SQLITE_OK)goto done;
    sqlite3_busy_timeout(s.db,5000);if(!store_exec(&s,"PRAGMA foreign_keys=ON",error,sizeof error))goto done;
    if(!prepare(&s,&q,"SELECT r.payload,r.fingerprint,r.review_token,r.keep_token,r.update_token,b.name_policy,r.plan_json FROM inventory_rows r JOIN inventory_batches b ON b.id=r.batch_id WHERE r.id=?1 AND r.lease_token=?2",error,sizeof error))goto done;
    sqlite3_bind_int64(q,1,id);text(q,2,lease);if(sqlite3_step(q)==SQLITE_ROW){payload=strdup((const char *)sqlite3_column_text(q,0));expected=strdup((const char *)sqlite3_column_text(q,1));old_review=strdup((const char *)sqlite3_column_text(q,2));old_keep=strdup((const char *)sqlite3_column_text(q,3));old_update=strdup((const char *)sqlite3_column_text(q,4));policy=strdup((const char *)sqlite3_column_text(q,5));old_plan=strdup((const char *)sqlite3_column_text(q,6));}sqlite3_finalize(q);q=NULL;
    if(!payload||!expected||!old_review||!old_keep||!old_update||!policy||!old_plan){fail(error,sizeof error,"Impossibile caricare la riga del lotto.");goto done;}
    if(!input_parse((const unsigned char *)payload,strlen(payload),&in,error,sizeof error))goto done;
    in.expected=commit?expected:NULL;in.policy=policy&&*policy?policy:NULL;
    if(!fetch(&in,&r,error,sizeof error)){needs_review=commit;goto done;}
    if(!store_exec(&s,"SAVEPOINT inventory_work",error,sizeof error))goto done;savepoint=1;
    if(!lease_valid(&s,id,lease,commit?"running":"planning",error,sizeof error))goto done;
    if(!make_plan(&s,&in,&r,&p,error,sizeof error))goto done;
    if(commit){
        /* Safe additive rebase for earlier rows in the same import. The
         * intended shared names must still be exactly those reviewed. */
        const char *compatible=policy&&!strcmp(policy,"update")?p.update_token:p.keep_token;
        const char *approved=policy&&!strcmp(policy,"update")?old_update:old_keep;
        if(strcmp(old_review,p.review)&&strcmp(compatible,approved)&&!sibling_rebase(&s,id,batch,&in,&p,old_plan,error,sizeof error)){fail(error,sizeof error,"Il registro è cambiato: serve una nuova approvazione per questa riga.");needs_review=1;goto done;}
        char key[160],digest[65];snprintf(key,sizeof key,"inventory-batch-%"PRId64"-row-%"PRId64,batch,id);input_hash(&in,r.certificates.items[0].fingerprint,digest);
        int found=receipt(&s,key,digest,&cert,error,sizeof error);if(found<0)goto done;
        if(!found&&(!apply_row(&s,&in,&r,&p,(int64_t)time(NULL),&cert,error,sizeof error)||!save_receipt(&s,key,digest,cert,error,sizeof error)))goto done;
        if(!record_row(&s,id,lease,"imported",NULL,NULL,cert,"",error,sizeof error))goto done;
    }else if(!record_row(&s,id,lease,"ready",&p,r.certificates.items[0].fingerprint,0,"",error,sizeof error))goto done;
    if(!store_exec(&s,"RELEASE inventory_work",error,sizeof error))goto done;savepoint=0;ok=1;
done:
    sqlite3_finalize(q);
    if(savepoint)rollback(&s,"inventory_work",1);
    if(s.db){if(!ok)record_row(&s,id,lease,needs_review?"needs_review":"error",NULL,NULL,0,*error?error:"Elaborazione interrotta.",local,sizeof local);finish_batch(&s,batch,local,sizeof local);}
    input_free(&in);remote_result_free(&r);plan_free(&p);free(payload);free(expected);free(old_review);free(old_keep);free(old_update);free(old_plan);free(policy);if(s.db)sqlite3_close(s.db);_exit(ok?0:1);
}
void inventory_shutdown(void){
    if(worker.pid>0){kill(-worker.pid,SIGKILL);kill(worker.pid,SIGKILL);while(waitpid(worker.pid,NULL,0)<0&&errno==EINTR){} }
    if(worker.owner&&worker.owner->db&&worker.id){sqlite3_stmt *q=NULL;if(sqlite3_prepare_v2(worker.owner->db,"UPDATE inventory_rows SET claim_until=0 WHERE id=?1 AND lease_token=?2",-1,&q,NULL)==SQLITE_OK){sqlite3_bind_int64(q,1,worker.id);text(q,2,worker.lease);sqlite3_step(q);}sqlite3_finalize(q);}
    memset(&worker,0,sizeof worker);
}
int inventory_tick(Store *s,int64_t now,char *err,size_t n){
    if(worker.pid>0){
        int result;pid_t pid=waitpid(worker.pid,&result,WNOHANG);
        if(pid==0&&now<worker.deadline)return 1;
        if(pid==0){kill(-worker.pid,SIGKILL);kill(worker.pid,SIGKILL);while(waitpid(worker.pid,&result,0)<0&&errno==EINTR){} }
        /* A crashed worker leaves a recoverable lease. A normal completed row
         * has already cleared it, so this update is harmless. */
        sqlite3_stmt *q=NULL;if(prepare(s,&q,"UPDATE inventory_rows SET claim_until=0 WHERE id=?1 AND lease_token=?2",err,n)){sqlite3_bind_int64(q,1,worker.id);text(q,2,worker.lease);sqlite3_step(q);}sqlite3_finalize(q);memset(&worker,0,sizeof worker);
    }
    const char *path=sqlite3_db_filename(s->db,"main");if(!path||!*path)return 1;
    int outer=sqlite3_get_autocommit(s->db);if(!store_exec(s,"SAVEPOINT inventory_claim",err,n))return 0;sqlite3_stmt *q=NULL;int64_t id=0,batch=0;int commit=0;int ok=prepare(s,&q,
        "SELECT r.id,r.batch_id,b.status FROM inventory_rows r JOIN inventory_batches b ON b.id=r.batch_id WHERE r.claim_until<=?1 AND ((b.status='planning' AND r.status IN('pending','checking')) OR (b.status='running' AND r.status IN('approved','importing'))) ORDER BY b.id,r.position LIMIT 1",err,n);
    if(ok){sqlite3_bind_int64(q,1,now);int rc=sqlite3_step(q);if(rc==SQLITE_ROW){id=sqlite3_column_int64(q,0);batch=sqlite3_column_int64(q,1);commit=!strcmp((const char *)sqlite3_column_text(q,2),"running");}else if(rc!=SQLITE_DONE)ok=dbfail(s,err,n);}sqlite3_finalize(q);q=NULL;
    unsigned char random[16];char lease[33]="";
    if(ok&&id){
        if(RAND_bytes(random,sizeof random)!=1)ok=fail(err,n,"Impossibile creare il lease di importazione.");
        else{for(size_t i=0;i<sizeof random;i++)snprintf(lease+i*2,3,"%02x",random[i]);ok=prepare(s,&q,"UPDATE inventory_rows SET status=?1,claim_until=?2,lease_token=?3 WHERE id=?4 AND claim_until<=?5",err,n);if(ok){text(q,1,commit?"importing":"checking");sqlite3_bind_int64(q,2,now+45);text(q,3,lease);sqlite3_bind_int64(q,4,id);sqlite3_bind_int64(q,5,now);ok=sqlite3_step(q)==SQLITE_DONE&&sqlite3_changes(s->db)==1;if(!ok)dbfail(s,err,n);}sqlite3_finalize(q);q=NULL;}
    }
    if(ok)ok=store_exec(s,"RELEASE inventory_claim",err,n);if(!ok){rollback(s,"inventory_claim",outer);return 0;}
    if(!id){
        /* Finish empty/retried batches even when every row was already ready. */
        sqlite3_stmt *b=NULL;if(prepare(s,&b,"SELECT id FROM inventory_batches WHERE status IN('planning','running')",err,n)){while(sqlite3_step(b)==SQLITE_ROW){int64_t bid=sqlite3_column_int64(b,0);if(!finish_batch(s,bid,err,n)){sqlite3_finalize(b);return 0;}}sqlite3_finalize(b);}return 1;
    }
    char *db_path=strdup(path);if(!db_path)return fail(err,n,"Memoria insufficiente.");
    pid_t pid=fork();if(!pid)process_row(db_path,id,batch,lease,commit);
    free(db_path);if(pid<0)return fail(err,n,"Impossibile avviare il processo di importazione.");
    (void)setpgid(pid,pid);worker.pid=pid;worker.deadline=now+25;worker.id=id;worker.owner=s;snprintf(worker.lease,sizeof worker.lease,"%s",lease);return 1;
}
