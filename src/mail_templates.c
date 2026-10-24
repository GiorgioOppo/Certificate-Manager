#define _POSIX_C_SOURCE 200809L
#include "mail_templates.h"
#include "workflow_support.h"
#include "chain.h"
#include "app.h"
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SUBJECT_MAX 998U
#define BODY_MAX 16384U
static const char *const alerts[]={"expiry_45","expiry_30","expiry_15","expiry_2","expired","expiry","escalation","certificate","unreachable","tls_error","changed","verification_error","error","recovered"};
static const char *const audiences[]={"self","business","technical","other"};
static const char *const variables[]={"app_name","common_name","fingerprint","not_before","not_after","serial","issuer","root_ca","intermediate_ca","sans","recipient_name","recipient_email","recipient_role","threshold","days_remaining","service_url","event_type","event_message","expected_fingerprint","observed_fingerprint"};
#define COUNT(a) (sizeof(a)/sizeof((a)[0]))
static int failure(char *err,size_t n,const char *msg){if(err&&n)snprintf(err,n,"%s",msg);return 0;}
static int dbfail(Store *s,char *err,size_t n){return failure(err,n,sqlite3_errmsg(s->db));}
static int known(const char *s,const char *const *list,size_t count){if(!s)return 0;for(size_t i=0;i<count;i++)if(!strcmp(s,list[i]))return 1;return 0;}
static void bind(sqlite3_stmt *q,int i,const char *s){sqlite3_bind_text(q,i,s?s:"",-1,SQLITE_TRANSIENT);}
static int plain(const char *s,size_t max,int multiline){
    if(!s||strlen(s)>max)return 0;const unsigned char *p=(const unsigned char*)s;
    while(*p){unsigned char c=*p++;if(c<32||c==127){if(multiline&&(c=='\n'||c=='\r'||c=='\t'))continue;return 0;}if(c<128)continue;
        int k;unsigned value;if(c>=0xc2&&c<=0xdf){k=1;value=c&31;}else if(c>=0xe0&&c<=0xef){k=2;value=c&15;}else if(c>=0xf0&&c<=0xf4){k=3;value=c&7;}else return 0;
        for(int i=0;i<k;i++){if((*p&0xc0)!=0x80)return 0;value=(value<<6)|(*p++&63);}if((k==2&&value<0x800)||(k==3&&value<0x10000)||value>0x10ffff||(value>=0xd800&&value<=0xdfff))return 0;
    }return 1;
}
const char *mail_templates_schema(void){return
    "CREATE TABLE mail_template_settings(id INTEGER PRIMARY KEY CHECK(id=1),self_name TEXT NOT NULL DEFAULT '',self_email TEXT NOT NULL DEFAULT '',updated_at INTEGER NOT NULL);"
    "INSERT INTO mail_template_settings(id,updated_at) VALUES(1,0);"
    "CREATE TABLE mail_templates(alert TEXT NOT NULL,audience TEXT NOT NULL CHECK(audience IN('self','business','technical','other')),subject TEXT NOT NULL,body TEXT NOT NULL,copy_enabled INTEGER NOT NULL DEFAULT 0 CHECK(copy_enabled IN(0,1)),updated_at INTEGER NOT NULL,PRIMARY KEY(alert,audience));"
    "ALTER TABLE outbox ADD COLUMN template_alert TEXT NOT NULL DEFAULT '';"
    "ALTER TABLE outbox ADD COLUMN template_audience TEXT NOT NULL DEFAULT '';"
    "ALTER TABLE outbox ADD COLUMN template_copy INTEGER NOT NULL DEFAULT 0 CHECK(template_copy IN(0,1));";
}
const char *mail_templates_expiry_alert(int threshold){switch(threshold){case 45:return "expiry_45";case 30:return "expiry_30";case 15:return "expiry_15";case 2:return "expiry_2";case 0:return "expired";default:return "expiry";}}
static const char *default_subject(const char *alert){
    if(!strncmp(alert,"expiry",6))return "Scadenza certificato HTTPS {{common_name}}: soglia {{threshold}} giorni";
    if(!strcmp(alert,"expired"))return "Certificato HTTPS scaduto: {{common_name}}";
    if(!strcmp(alert,"escalation"))return "Escalation rinnovo certificato HTTPS {{common_name}}";
    if(!strcmp(alert,"certificate"))return "Certificato HTTPS firmato per {{common_name}} - validità fino al {{not_after}}";
    if(!strcmp(alert,"recovered"))return "Monitor HTTPS {{service_url}}: servizio ripristinato";
    return "Monitor HTTPS {{service_url}}: {{event_type}}";
}
static char *default_body(const char *alert,const char *audience){
    const char *greeting=!strcmp(audience,"technical")?"Gentile referente tecnico":!strcmp(audience,"business")?"Gentile referente":!strcmp(audience,"self")?"Riepilogo personale":"Gentile destinatario";
    const char *text;
    if(!strcmp(alert,"certificate"))text="in allegato è disponibile il certificato HTTPS firmato per {{common_name}}, con scadenza il {{not_after}}.\nInstallare il certificato e verificare il servizio secondo le procedure previste.\nL'allegato contiene esclusivamente certificati pubblici e non include chiavi private.";
    else if(!strcmp(alert,"escalation"))text="il certificato HTTPS {{common_name}} scade il {{not_after}}.\nÈ trascorso il periodo di escalation dal primo promemoria registrato.\nVerificare il rinnovo e l'installazione su tutti i servizi interessati.";
    else if(!strncmp(alert,"expiry",6)||!strcmp(alert,"expired"))text="il certificato HTTPS {{common_name}} ha scadenza il {{not_after}}.\nSoglia rilevata: {{threshold}} giorni prima della scadenza (0 indica un certificato scaduto).\nGiorni rimanenti: {{days_remaining}}.\nSi richiede di pianificare o verificare il rinnovo con il referente tecnico.";
    else text="Monitor del servizio HTTPS {{service_url}}\n\n{{event_message}}\n\nImpronta prevista: {{expected_fingerprint}}\nImpronta osservata: {{observed_fingerprint}}\n\nControllare il servizio e il registro dei certificati. Un certificato inatteso non viene approvato automaticamente.";
    size_t size=strlen(greeting)+strlen(text)+100;char *result=malloc(size);if(result)snprintf(result,size,"%s {{recipient_name}},\n\n%s\n\nGestione certificati HTTPS\n",greeting,text);return result;
}
static int load_template(Store *s,const char *alert,const char *audience,char **subject,char **body,int *copy,int *customized,char *err,size_t n){
    *subject=NULL;*body=NULL;*copy=0;*customized=0;sqlite3_stmt *q=NULL;
    if(sqlite3_prepare_v2(s->db,"SELECT subject,body,copy_enabled FROM mail_templates WHERE alert=?1 AND audience=?2",-1,&q,NULL)!=SQLITE_OK)return dbfail(s,err,n);bind(q,1,alert);bind(q,2,audience);int rc=sqlite3_step(q);
    if(rc==SQLITE_ROW){*subject=strdup((const char*)sqlite3_column_text(q,0));*body=strdup((const char*)sqlite3_column_text(q,1));*copy=sqlite3_column_int(q,2);*customized=1;}
    else if(rc==SQLITE_DONE){*subject=strdup(default_subject(alert));*body=default_body(alert,audience);}else{sqlite3_finalize(q);return dbfail(s,err,n);}sqlite3_finalize(q);
    if(!*subject||!*body){free(*subject);free(*body);*subject=NULL;*body=NULL;return failure(err,n,"Memoria insufficiente.");}return 1;
}
static int variable_index(const char *p,size_t length){for(size_t i=0;i<COUNT(variables);i++)if(strlen(variables[i])==length&&!strncmp(p,variables[i],length))return (int)i;return -1;}
static int validate_template(const char *s,size_t max,int multiline,char *err,size_t n){
    if(!plain(s,max,multiline)||!*s)return failure(err,n,"Testo email non valido, vuoto o troppo lungo.");
    for(const char *p=s;*p;){if(*p=='{'||*p=='}'){if(p[0]!='{'||p[1]!='{')return failure(err,n,"Variabile malformata: usa {{nome_variabile}}.");const char *end=strstr(p+2,"}}");if(!end||variable_index(p+2,(size_t)(end-p-2))<0)return failure(err,n,"Variabile email sconosciuta o malformata.");p=end+2;}else p++;}return 1;
}
static int expand(const char *text,char **values,size_t max,int multiline,char **result,char *err,size_t n){
    *result=NULL;size_t used=0;char *out=malloc(max+1);if(!out)return failure(err,n,"Memoria insufficiente.");
    for(const char *p=text;*p;){const char *value=p;size_t length=1;if(p[0]=='{'&&p[1]=='{'){const char *end=strstr(p+2,"}}");int index=end?variable_index(p+2,(size_t)(end-p-2)):-1;if(index<0){free(out);return failure(err,n,"Variabile email sconosciuta.");}value=values[index]?values[index]:"";length=strlen(value);p=end+2;}else p++;
        if(length>max-used){free(out);return failure(err,n,"Il messaggio espanso supera la lunghezza consentita.");}memcpy(out+used,value,length);used+=length;
    }out[used]=0;if(!plain(out,max,multiline)){free(out);return failure(err,n,"Dati non validi per il messaggio email; oggetto senza ritorni a capo.");}*result=out;return 1;
}
static char *date_text(int64_t epoch){time_t at=(time_t)epoch;struct tm tm;char result[64];if((int64_t)at!=epoch||!gmtime_r(&at,&tm)||!strftime(result,sizeof result,"%d/%m/%Y alle %H:%M UTC",&tm))return NULL;return strdup(result);}
static int set_number(char **p,int64_t v){char text[64];snprintf(text,sizeof text,"%"PRId64,v);*p=strdup(text);return *p!=NULL;}
int mail_templates_render(Store *s,const char *alert,const char *audience,int64_t cert_id,int64_t event_id,int threshold,int64_t now,const char *recipient_name,const char *recipient_email,const char *subject_override,const char *body_override,char **subject,char **body,char *err,size_t n){
    *subject=NULL;*body=NULL;if(!known(alert,alerts,COUNT(alerts))||!known(audience,audiences,COUNT(audiences)))return failure(err,n,"Tipo di avviso o destinatario non valido.");
    char *source_subject=NULL,*source_body=NULL,*values[COUNT(variables)]={0};int copy,customized,ok=0;sqlite3_stmt *q=NULL;CertificateChain chain={0};
    if(subject_override||body_override){if(!subject_override||!body_override)return failure(err,n,"Indica oggetto e testo.");source_subject=strdup(subject_override);source_body=strdup(body_override);if(!source_subject||!source_body)goto memory;}
    else if(!load_template(s,alert,audience,&source_subject,&source_body,&copy,&customized,err,n))goto done;
    if(!validate_template(source_subject,SUBJECT_MAX,0,err,n)||!validate_template(source_body,BODY_MAX,1,err,n))goto done;
    if(event_id>0&&cert_id==0){if(sqlite3_prepare_v2(s->db,"SELECT monitor.certificate_id FROM monitor_events event JOIN monitors monitor ON monitor.id=event.monitor_id WHERE event.id=?1",-1,&q,NULL)!=SQLITE_OK)goto database;sqlite3_bind_int64(q,1,event_id);if(sqlite3_step(q)!=SQLITE_ROW){failure(err,n,"Evento del servizio non trovato.");goto done;}cert_id=sqlite3_column_int64(q,0);sqlite3_finalize(q);q=NULL;}
    values[0]=strdup("Certificate Manager");values[10]=strdup(recipient_name?recipient_name:"Destinatario Demo");values[11]=strdup(recipient_email?recipient_email:"destinatario@example.test");values[12]=strdup(audience);if(!set_number(&values[13],threshold))goto memory;
    if(cert_id>0){if(sqlite3_prepare_v2(s->db,"SELECT common_name,fingerprint,not_before,not_after,serial,issuer,sans FROM certificates WHERE id=?1",-1,&q,NULL)!=SQLITE_OK)goto database;sqlite3_bind_int64(q,1,cert_id);if(sqlite3_step(q)!=SQLITE_ROW){failure(err,n,"Certificato non trovato.");goto done;}int64_t expiry=sqlite3_column_int64(q,3);
        values[1]=strdup((const char*)sqlite3_column_text(q,0));values[2]=strdup((const char*)sqlite3_column_text(q,1));values[3]=date_text(sqlite3_column_int64(q,2));values[4]=date_text(expiry);values[5]=strdup((const char*)sqlite3_column_text(q,4));values[6]=strdup((const char*)sqlite3_column_text(q,5));values[9]=strdup((const char*)sqlite3_column_text(q,6));if(!set_number(&values[14],app_days_remaining(expiry,now)))goto memory;sqlite3_finalize(q);q=NULL;
        if(!chain_describe(s,cert_id,&chain,err,n))goto done;values[7]=strdup(chain.root_ca?chain.root_ca:"");values[8]=strdup(chain.intermediate_ca?chain.intermediate_ca:"");
    }else{const char *samples[]={"www.example.test","A1:B2:C3:DEMO","","","DEMO-1234","CN=Example Intermediate CA","Example Root CA","Example Intermediate CA","DNS:www.example.test"};for(size_t i=0;i<9;i++)if(i!=2&&i!=3)values[i+1]=strdup(samples[i]);int days=!strcmp(alert,"expired")?-1:!strncmp(alert,"expiry",6)&&threshold>=0?threshold:!strcmp(alert,"certificate")?365:!strcmp(alert,"escalation")?7:30;int64_t sample_expiry=now+(int64_t)days*86400;values[3]=date_text(now-90*INT64_C(86400));values[4]=date_text(sample_expiry);if(!set_number(&values[14],app_days_remaining(sample_expiry,now)))goto memory;}
    if(event_id>0){if(sqlite3_prepare_v2(s->db,"SELECT monitor.target,event.kind,event.message,event.expected_fingerprint,event.observed_fingerprint FROM monitor_events event JOIN monitors monitor ON monitor.id=event.monitor_id WHERE event.id=?1 AND (?2=0 OR monitor.certificate_id=?2)",-1,&q,NULL)!=SQLITE_OK)goto database;sqlite3_bind_int64(q,1,event_id);sqlite3_bind_int64(q,2,cert_id);if(sqlite3_step(q)!=SQLITE_ROW){failure(err,n,"Evento del servizio non trovato per questo certificato.");goto done;}for(int i=0;i<5;i++)values[15+i]=strdup((const char*)sqlite3_column_text(q,i));sqlite3_finalize(q);q=NULL;
    }else{values[15]=strdup(cert_id?"":"https://www.example.test:443");values[16]=strdup(alert);values[17]=strdup(cert_id?"":"Esempio di segnalazione del servizio HTTPS.");values[18]=strdup(values[2]?values[2]:"");values[19]=strdup(cert_id?"":"D4:E5:F6:DEMO");}
    for(size_t i=0;i<COUNT(values);i++)if(!values[i])goto memory;
    if(!expand(source_subject,values,SUBJECT_MAX,0,subject,err,n)||!expand(source_body,values,BODY_MAX,1,body,err,n))goto done;ok=1;goto done;
    database:dbfail(s,err,n);goto done;
    memory:failure(err,n,"Memoria insufficiente o data non rappresentabile.");
    done:sqlite3_finalize(q);chain_free(&chain);free(source_subject);free(source_body);for(size_t i=0;i<COUNT(values);i++)free(values[i]);if(!ok){free(*subject);free(*body);*subject=NULL;*body=NULL;}return ok;
}
char *mail_templates_audience(Store *s,int64_t cert_id,const char *email,char *err,size_t n){
    sqlite3_stmt *q=NULL;const char *sql="SELECT CASE WHEN EXISTS(SELECT 1 FROM mail_template_settings WHERE id=1 AND self_email<>'' AND self_email=?2 COLLATE NOCASE) THEN 'self' WHEN EXISTS(SELECT 1 FROM contacts WHERE certificate_id=?1 AND email=?2 COLLATE NOCASE AND role='business') THEN 'business' WHEN EXISTS(SELECT 1 FROM contacts WHERE certificate_id=?1 AND email=?2 COLLATE NOCASE AND role='technical') THEN 'technical' ELSE 'other' END";
    if(sqlite3_prepare_v2(s->db,sql,-1,&q,NULL)!=SQLITE_OK){dbfail(s,err,n);return NULL;}sqlite3_bind_int64(q,1,cert_id);bind(q,2,email);char *result=NULL;if(sqlite3_step(q)==SQLITE_ROW)result=strdup((const char*)sqlite3_column_text(q,0));else dbfail(s,err,n);sqlite3_finalize(q);return result;
}
static int state(Store *s,FILE *out,char *err,size_t n){
    fputs("{\"settings\":",out);sqlite3_stmt *q=NULL;if(sqlite3_prepare_v2(s->db,"SELECT self_name,self_email FROM mail_template_settings WHERE id=1",-1,&q,NULL)!=SQLITE_OK)return dbfail(s,err,n);if(sqlite3_step(q)!=SQLITE_ROW){sqlite3_finalize(q);return dbfail(s,err,n);}fputs("{\"self_name\":",out);app_json_string(out,(const char*)sqlite3_column_text(q,0));fputs(",\"self_email\":",out);app_json_string(out,(const char*)sqlite3_column_text(q,1));fputc('}',out);sqlite3_finalize(q);
    fputs(",\"alerts\":[",out);for(size_t i=0;i<COUNT(alerts);i++){if(i)fputc(',',out);fputs("{\"id\":",out);app_json_string(out,alerts[i]);fputc('}',out);}fputs("],\"audiences\":[",out);for(size_t i=0;i<COUNT(audiences);i++){if(i)fputc(',',out);fputs("{\"id\":",out);app_json_string(out,audiences[i]);fputc('}',out);}fputs("],\"variables\":[",out);for(size_t i=0;i<COUNT(variables);i++){if(i)fputc(',',out);app_json_string(out,variables[i]);}fputs("],\"templates\":[",out);int first=1;
    for(size_t i=0;i<COUNT(alerts);i++)for(size_t j=0;j<COUNT(audiences);j++){char *subject=NULL,*body=NULL;int copy,customized;if(!load_template(s,alerts[i],audiences[j],&subject,&body,&copy,&customized,err,n))return 0;if(!first)fputc(',',out);first=0;fputs("{\"alert\":",out);app_json_string(out,alerts[i]);fputs(",\"audience\":",out);app_json_string(out,audiences[j]);fputs(",\"subject\":",out);app_json_string(out,subject);fputs(",\"body\":",out);app_json_string(out,body);fprintf(out,",\"copy_enabled\":%s,\"customized\":%s}",copy?"true":"false",customized?"true":"false");free(subject);free(body);}
    fputs("]}",out);return 1;
}
static void rollback(Store *s,int outer){sqlite3_exec(s->db,outer?"ROLLBACK":"ROLLBACK TO mail_template_edit; RELEASE mail_template_edit",NULL,NULL,NULL);}
char *mail_templates_api(Store *s,const char *method,const char *path,const unsigned char *body,size_t body_len,size_t *length,int *status,char *err,size_t n){
    if(err&&n)err[0]=0;*length=0;*status=400;if(body_len>131072){failure(err,n,"Richiesta troppo grande.");return NULL;}char *result=NULL;FILE *out=NULL;WFForm f={0};int ok=0;
    if(!strcmp(method,"GET")&&!strcmp(path,"/api/mail-templates/state")){out=open_memstream(&result,length);if(!out)goto memory;ok=state(s,out,err,n);goto done;}
    if(!wf_form_parse(body,body_len,&f,err,n))goto done;
    const char *alert=wf_get(&f,"alert"),*audience=wf_get(&f,"audience"),*subject=wf_get(&f,"subject"),*content=wf_get(&f,"body");
    if(!strcmp(method,"POST")&&!strcmp(path,"/api/mail-templates/preview")){
        if(!known(alert,alerts,COUNT(alerts))||!known(audience,audiences,COUNT(audiences))){failure(err,n,"Tipo di avviso o destinatario non valido.");goto done;}
        int64_t cert=0,event=0;if(wf_count(&f,"certificate_id")&&!wf_number(wf_get(&f,"certificate_id"),1,INT64_MAX,&cert)){failure(err,n,"Certificato non valido.");goto done;}if(wf_count(&f,"event_id")&&!wf_number(wf_get(&f,"event_id"),1,INT64_MAX,&event)){failure(err,n,"Evento non valido.");goto done;}
        int threshold=!alert?-1:!strcmp(alert,"expired")?0:!strncmp(alert,"expiry_",7)?atoi(alert+7):!strcmp(alert,"expiry")?7:-1;char *rendered_subject=NULL,*rendered_body=NULL;
        if(!mail_templates_render(s,alert,audience,cert,event,threshold,(int64_t)time(NULL),NULL,NULL,subject,content,&rendered_subject,&rendered_body,err,n))goto done;
        out=open_memstream(&result,length);if(!out){free(rendered_subject);free(rendered_body);goto memory;}fputs("{\"subject\":",out);app_json_string(out,rendered_subject);fputs(",\"body\":",out);app_json_string(out,rendered_body);fprintf(out,",\"attachment\":%s,\"sample\":%s}",!strcmp(alert,"certificate")?"true":"false",cert||event?"false":"true");free(rendered_subject);free(rendered_body);ok=1;
    }else if((!strcmp(method,"PUT")&&!strcmp(path,"/api/mail-templates/settings"))||(!strcmp(method,"PUT")&&!strcmp(path,"/api/mail-templates/template"))||(!strcmp(method,"POST")&&!strcmp(path,"/api/mail-templates/reset"))){
        int settings=!strcmp(path,"/api/mail-templates/settings"),reset=!strcmp(path,"/api/mail-templates/reset");int64_t copy=0;const char *name=wf_get(&f,"self_name"),*email=wf_get(&f,"self_email");
        if(settings){if(!plain(name,120,0)||!email||(*email&&!store_email_valid(email))){failure(err,n,"Nome o email personale non validi.");goto done;}}
        else{if(!known(alert,alerts,COUNT(alerts))||!known(audience,audiences,COUNT(audiences))){failure(err,n,"Tipo di avviso o destinatario non valido.");goto done;}if(!reset&&(!validate_template(subject,SUBJECT_MAX,0,err,n)||!validate_template(content,BODY_MAX,1,err,n)||!wf_number(wf_get(&f,"copy_enabled"),0,1,&copy)||(!strcmp(audience,"other")&&copy))){if(err&&n&&!err[0])failure(err,n,"Impostazione copie non valida.");goto done;}}
        if(!settings&&!reset&&copy&&!strcmp(audience,"self")){sqlite3_stmt *owner=NULL;if(sqlite3_prepare_v2(s->db,"SELECT self_email FROM mail_template_settings WHERE id=1",-1,&owner,NULL)!=SQLITE_OK){dbfail(s,err,n);goto done;}int rc=sqlite3_step(owner);int configured=rc==SQLITE_ROW&&store_email_valid((const char*)sqlite3_column_text(owner,0));sqlite3_finalize(owner);if(!configured){failure(err,n,"Configura prima il tuo indirizzo email personale.");goto done;}}
        int outer=sqlite3_get_autocommit(s->db);if(!store_exec(s,"SAVEPOINT mail_template_edit",err,n))goto done;sqlite3_stmt *q=NULL;
        const char *sql=settings?"UPDATE mail_template_settings SET self_name=?1,self_email=?2,updated_at=?3 WHERE id=1":reset?"DELETE FROM mail_templates WHERE alert=?1 AND audience=?2":"INSERT INTO mail_templates(alert,audience,subject,body,copy_enabled,updated_at) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(alert,audience) DO UPDATE SET subject=excluded.subject,body=excluded.body,copy_enabled=excluded.copy_enabled,updated_at=excluded.updated_at";
        ok=sqlite3_prepare_v2(s->db,sql,-1,&q,NULL)==SQLITE_OK;if(ok){bind(q,1,settings?name:alert);bind(q,2,settings?email:audience);if(settings)sqlite3_bind_int64(q,3,(int64_t)time(NULL));else if(!reset){bind(q,3,subject);bind(q,4,content);sqlite3_bind_int(q,5,(int)copy);sqlite3_bind_int64(q,6,(int64_t)time(NULL));}ok=sqlite3_step(q)==SQLITE_DONE;}if(!ok)dbfail(s,err,n);sqlite3_finalize(q);
        if(ok){char detail[160];snprintf(detail,sizeof detail,"%s%s%s",settings?"settings":alert,settings?"":"/",settings?"":audience);ok=wf_audit(s,"mail_templates",0,reset?"reset":settings?"settings":"update",detail,err,n);}if(ok)ok=store_exec(s,"RELEASE mail_template_edit",err,n);if(!ok){rollback(s,outer);goto done;}
        result=strdup("{\"ok\":true}");if(!result)goto memory;*length=strlen(result);
    }else{*status=404;failure(err,n,"Operazione non trovata.");}
    goto done;
    memory:failure(err,n,"Memoria insufficiente.");ok=0;
    done:wf_form_free(&f);if(out){if(ferror(out))ok=0;if(fclose(out))ok=0;}if(!ok){free(result);return NULL;}*status=200;return result;
}
