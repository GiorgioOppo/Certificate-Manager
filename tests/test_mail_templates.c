#define _POSIX_C_SOURCE 200809L
#include "mail_templates.h"
#include "delivery.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char error[512];
static const int64_t now=INT64_C(2100000000);
#define REQUIRE(c) do{if(!(c)){fprintf(stderr,"%s:%d %s: %s\n",__FILE__,__LINE__,#c,error);exit(1);}}while(0)
static void sql(Store *s,const char *text){REQUIRE(store_exec(s,text,error,sizeof error));}
static int scalar(Store *s,const char *text){sqlite3_stmt *q=NULL;REQUIRE(sqlite3_prepare_v2(s->db,text,-1,&q,NULL)==SQLITE_OK);REQUIRE(sqlite3_step(q)==SQLITE_ROW);int v=sqlite3_column_int(q,0);sqlite3_finalize(q);return v;}
static char *text_scalar(Store *s,const char *text){sqlite3_stmt *q=NULL;REQUIRE(sqlite3_prepare_v2(s->db,text,-1,&q,NULL)==SQLITE_OK);REQUIRE(sqlite3_step(q)==SQLITE_ROW);char *v=strdup((const char*)sqlite3_column_text(q,0));REQUIRE(v);sqlite3_finalize(q);return v;}
static char *api(Store *s,const char *method,const char *path,const char *form,int expected){size_t length=0;int status=0;char *r=mail_templates_api(s,method,path,(const unsigned char*)form,strlen(form),&length,&status,error,sizeof error);REQUIRE(status==expected);REQUIRE((expected==200)==(r!=NULL));if(r)REQUIRE(strlen(r)==length);return r;}
static char *public_pem(void){
    EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,NULL);EVP_PKEY *key=NULL;REQUIRE(ctx&&EVP_PKEY_keygen_init(ctx)>0&&EVP_PKEY_CTX_set_rsa_keygen_bits(ctx,2048)>0&&EVP_PKEY_keygen(ctx,&key)>0);EVP_PKEY_CTX_free(ctx);
    X509 *x=X509_new();REQUIRE(x&&X509_set_version(x,2)&&ASN1_INTEGER_set(X509_get_serialNumber(x),1)&&X509_gmtime_adj(X509_getm_notBefore(x),0)&&X509_gmtime_adj(X509_getm_notAfter(x),86400)&&X509_set_pubkey(x,key));X509_NAME *name=X509_NAME_new();REQUIRE(name&&X509_NAME_add_entry_by_txt(name,"CN",MBSTRING_ASC,(const unsigned char*)"www.example.test",-1,-1,0)&&X509_set_subject_name(x,name)&&X509_set_issuer_name(x,name)&&X509_sign(x,key,EVP_sha256())>0);X509_NAME_free(name);BIO *bio=BIO_new(BIO_s_mem());REQUIRE(bio&&PEM_write_bio_X509(bio,x));char *p=NULL;long n=BIO_get_mem_data(bio,&p);REQUIRE(n>0);char *result=strndup(p,(size_t)n);REQUIRE(result);BIO_free(bio);X509_free(x);EVP_PKEY_free(key);return result;
}
static void setup(Store *s,char *pem){
    REQUIRE(store_open(s,":memory:",error,sizeof error));Certificate c={.common_name="www.example.test",.subject="CN=www.example.test",.issuer="CN=Example CA",.serial="1234",.sans="DNS:www.example.test",.fingerprint="template-test",.key_algorithm="RSA",.signature_algorithm="sha256WithRSAEncryption",.key_bits=2048,.not_before=now-86400,.not_after=now+30*86400,.pem=pem};int64_t id=0;int inserted=0;REQUIRE(store_add(s,&c,"test.pem",now,&id,&inserted,error,sizeof error));REQUIRE(id==1&&inserted);
    sql(s,"INSERT INTO contacts VALUES(1,'business','Anna','anna@example.test'); INSERT INTO contacts VALUES(1,'technical','Marco','marco@example.test'); INSERT INTO smtp_settings(id,enabled,host,port,security,from_email,username,password_cipher,updated_at) VALUES(1,0,'',587,'starttls','','','',0)");
}
static void test_render_and_validation(Store *s){
    char *subject=NULL,*body=NULL;REQUIRE(mail_templates_render(s,"expiry_30","business",1,0,30,now,"Anna","anna@example.test",NULL,NULL,&subject,&body,error,sizeof error));REQUIRE(strstr(subject,"www.example.test")&&strstr(subject,"30"));REQUIRE(strstr(body,"Anna")&&strstr(body,"30"));free(subject);free(body);
    const char *names[]={"self","business","technical","other"};const char *alerts[]={"expiry_45","expiry_30","expiry_15","expiry_2","expired","expiry","escalation","certificate","unreachable","tls_error","changed","verification_error","error","recovered"};
    int changes=sqlite3_total_changes(s->db);for(size_t i=0;i<14;i++)for(size_t j=0;j<4;j++){REQUIRE(mail_templates_render(s,alerts[i],names[j],0,0,30,now,NULL,NULL,NULL,NULL,&subject,&body,error,sizeof error));REQUIRE(!strstr(subject,"{{")&&!strstr(body,"{{"));free(subject);free(body);}REQUIRE(sqlite3_total_changes(s->db)==changes);
    char *r=api(s,"POST","/api/mail-templates/preview","alert=certificate&audience=technical&subject=Certificato+%7B%7Bcommon_name%7D%7D&body=Ciao+%7B%7Brecipient_name%7D%7D",200);REQUIRE(strstr(r,"\"attachment\":true")&&strstr(r,"\"sample\":true"));free(r);REQUIRE(sqlite3_total_changes(s->db)==changes);
    free(api(s,"PUT","/api/mail-templates/template","alert=expiry_30&audience=business&subject=%7B%7Bunknown%7D%7D&body=Test&copy_enabled=0",400));
    free(api(s,"PUT","/api/mail-templates/template","alert=expiry_30&audience=business&subject=Injected%0D%0ABcc%3Aevil%40example.test&body=Test&copy_enabled=0",400));
    free(api(s,"PUT","/api/mail-templates/template","alert=expiry_30&audience=business&subject=Bad+%7B%7Bcommon_name%7D&body=Test&copy_enabled=0",400));
    free(api(s,"PUT","/api/mail-templates/template","alert=expiry_30&audience=other&subject=Test&body=Test&copy_enabled=1",400));
    free(api(s,"PUT","/api/mail-templates/settings","self_name=Bad%0AName&self_email=me%40example.test",400));
    free(api(s,"PUT","/api/mail-templates/template","alert=expiry_30&audience=self&subject=Test&body=Test&copy_enabled=1",400));
    free(api(s,"POST","/api/mail-templates/preview","alert=expiry_99999999999999999999999999999999999999999999&audience=self&subject=Test&body=Test",400));
    REQUIRE(sqlite3_total_changes(s->db)==changes);
    sql(s,"UPDATE certificates SET common_name='bad'||char(10)||'Bcc: victim@example.test' WHERE id=1");REQUIRE(!mail_templates_render(s,"expiry_30","business",1,0,30,now,"Anna","anna@example.test",NULL,NULL,&subject,&body,error,sizeof error));sql(s,"UPDATE certificates SET common_name='www.example.test' WHERE id=1");
}
static void test_snapshot_and_copy_controls(Store *s,char *pem){
    REQUIRE(delivery_queue_expiry(s,1,45,now,error,sizeof error));REQUIRE(scalar(s,"SELECT count(*) FROM outbox")==1);REQUIRE(scalar(s,"SELECT count(*) FROM outbox WHERE template_alert='expiry_45' AND template_audience='business' AND template_copy=0")==1);
    free(api(s,"PUT","/api/mail-templates/settings","self_name=Me&self_email=me%40example.test",200));
    free(api(s,"PUT","/api/mail-templates/template","alert=expiry_30&audience=self&subject=My+%7B%7Bcommon_name%7D%7D&body=Private+%7B%7Brecipient_email%7D%7D&copy_enabled=1",200));
    free(api(s,"PUT","/api/mail-templates/template","alert=expiry_30&audience=business&subject=Business+%7B%7Brecipient_name%7D%7D&body=Thirty+%7B%7Bthreshold%7D%7D&copy_enabled=1",200));
    free(api(s,"PUT","/api/mail-templates/template","alert=expiry_30&audience=technical&subject=Tech+%7B%7Brecipient_name%7D%7D&body=Prepare+renewal&copy_enabled=1",200));
    REQUIRE(delivery_queue_expiry(s,1,30,now,error,sizeof error));REQUIRE(scalar(s,"SELECT count(*) FROM outbox")==3);REQUIRE(scalar(s,"SELECT count(*) FROM outbox WHERE template_copy=1")==2);REQUIRE(scalar(s,"SELECT count(*) FROM outbox WHERE template_audience='business' AND template_copy=0 AND subject='Business Anna'")==1);
    char *snapshot=text_scalar(s,"SELECT body FROM outbox WHERE recipient_email='me@example.test'");REQUIRE(strstr(snapshot,"Private me@example.test"));
    free(api(s,"PUT","/api/mail-templates/template","alert=expiry_30&audience=self&subject=New+subject&body=Changed+body&copy_enabled=1",200));char *same=text_scalar(s,"SELECT body FROM outbox WHERE recipient_email='me@example.test'");REQUIRE(!strcmp(snapshot,same));free(same);free(snapshot);
    REQUIRE(delivery_queue_expiry(s,1,30,now,error,sizeof error));REQUIRE(scalar(s,"SELECT count(*) FROM outbox")==3);
    free(api(s,"POST","/api/mail-templates/reset","alert=expiry_30&audience=technical",200));int sent=-1;REQUIRE(delivery_process(s,now,&sent,error,sizeof error)&&sent==0);REQUIRE(scalar(s,"SELECT count(*) FROM outbox WHERE recipient_email='marco@example.test'")==0);REQUIRE(scalar(s,"SELECT count(*) FROM outbox WHERE recipient_email='anna@example.test'")==1);
    free(api(s,"PUT","/api/mail-templates/settings","self_name=Me&self_email=new%40example.test",200));REQUIRE(delivery_process(s,now,&sent,error,sizeof error));REQUIRE(scalar(s,"SELECT count(*) FROM outbox WHERE recipient_email='me@example.test'")==0);
    /* The same mailbox in the owner profile and both contact roles gets one
     * baseline message; its routing template wins over optional copies. */
    free(api(s,"PUT","/api/mail-templates/settings","self_name=Anna&self_email=anna%40example.test",200));free(api(s,"PUT","/api/mail-templates/template","alert=expiry_15&audience=self&subject=Mine&body=Mine&copy_enabled=1",200));sql(s,"INSERT INTO contacts VALUES(1,'technical','Anna','ANNA@example.test')");REQUIRE(delivery_queue_expiry(s,1,15,now,error,sizeof error));REQUIRE(scalar(s,"SELECT count(*) FROM outbox")==1);REQUIRE(scalar(s,"SELECT count(*) FROM outbox WHERE template_copy=0 AND template_audience='business'")==1);
    char *audience=mail_templates_audience(s,1,"ANNA@example.test",error,sizeof error);REQUIRE(audience&&!strcmp(audience,"self"));free(audience);
    int queued=0;REQUIRE(delivery_queue_certificate(s,1,pem,now,&queued,error,sizeof error)&&queued==2);REQUIRE(scalar(s,"SELECT count(*) FROM outbox WHERE kind='certificate' AND attachment_pem<>'' AND template_audience='technical'")==2);
    free(api(s,"PUT","/api/mail-templates/template","alert=certificate&audience=self&subject=Signed&body=Public+certificate&copy_enabled=1",200));REQUIRE(delivery_queue_certificate(s,1,pem,now,&queued,error,sizeof error)&&queued==0);
    sql(s,"UPDATE mail_template_settings SET self_email='copy@example.test' WHERE id=1");REQUIRE(delivery_queue_certificate(s,1,pem,now,&queued,error,sizeof error)&&queued==1);REQUIRE(scalar(s,"SELECT count(*) FROM outbox WHERE kind='certificate' AND recipient_email='copy@example.test' AND template_copy=1 AND attachment_pem<>''")==1);
}
static void test_monitor_and_escalation(char *pem){
    Store s;setup(&s,pem);int queued=0,sent=0;
    free(api(&s,"PUT","/api/mail-templates/settings","self_name=Me&self_email=me%40example.test",200));
    sql(&s,"INSERT INTO monitors(certificate_id,target,email_alerts,created_at,updated_at) VALUES(1,'https://service.example.test:443',1,2100000000,2100000000); INSERT INTO monitor_recipients VALUES(1,'Me','me@example.test'),(1,'Anna','anna@example.test'),(1,'Marco','marco@example.test'),(1,'Ops','ops@example.test'); INSERT INTO monitor_events(monitor_id,kind,message,expected_fingerprint,observed_fingerprint,created_at) VALUES(1,'changed','Certificato differente','EXPECTED','OBSERVED',2100000000)");
    const char *forms[]={"alert=changed&audience=self&subject=SELF+%7B%7Bevent_type%7D%7D&body=%7B%7Bservice_url%7D%7D&copy_enabled=1","alert=changed&audience=business&subject=BUSINESS&body=%7B%7Bevent_message%7D%7D&copy_enabled=1","alert=changed&audience=technical&subject=TECHNICAL&body=%7B%7Bobserved_fingerprint%7D%7D&copy_enabled=1","alert=changed&audience=other&subject=OTHER&body=%7B%7Bexpected_fingerprint%7D%7D&copy_enabled=0"};
    for(int i=0;i<4;i++)free(api(&s,"PUT","/api/mail-templates/template",forms[i],200));
    REQUIRE(delivery_queue_monitor_event(&s,1,now,&queued,error,sizeof error)&&queued==4);REQUIRE(scalar(&s,"SELECT count(*) FROM outbox WHERE kind='monitor' AND template_copy=0")==4);REQUIRE(scalar(&s,"SELECT count(*) FROM outbox WHERE template_audience='self' AND subject='SELF changed' AND body='https://service.example.test:443'")==1);REQUIRE(scalar(&s,"SELECT count(*) FROM outbox WHERE template_audience='other' AND subject='OTHER' AND body='EXPECTED'")==1);
    sql(&s,"INSERT INTO contacts VALUES(1,'business','Extra','extra@example.test'); INSERT INTO monitor_events(monitor_id,kind,message,expected_fingerprint,observed_fingerprint,created_at) VALUES(1,'changed','Altro certificato','EXPECTED','SECOND',2100000001)");
    REQUIRE(delivery_queue_monitor_event(&s,2,now+1,&queued,error,sizeof error)&&queued==5);REQUIRE(scalar(&s,"SELECT count(*) FROM outbox WHERE event_id=2 AND recipient_email='extra@example.test' AND template_copy=1")==1);sql(&s,"DELETE FROM contacts WHERE email='extra@example.test'");REQUIRE(delivery_process(&s,now+2,&sent,error,sizeof error));REQUIRE(scalar(&s,"SELECT count(*) FROM outbox WHERE recipient_email='extra@example.test'")==0);
    char *preview=api(&s,"POST","/api/mail-templates/preview","alert=changed&audience=other&event_id=2&subject=%7B%7Bcommon_name%7D%7D&body=%7B%7Bobserved_fingerprint%7D%7D",200);REQUIRE(strstr(preview,"www.example.test")&&strstr(preview,"SECOND")&&strstr(preview,"\"sample\":false"));free(preview);
    /* Owner matching a contact takes the personal template among optional
     * copies, while the explicit base recipients still take precedence. */
    free(api(&s,"PUT","/api/mail-templates/settings","self_name=Anna&self_email=anna%40example.test",200));
    sql(&s,"DELETE FROM monitor_recipients WHERE email='anna@example.test'; INSERT INTO monitor_events(monitor_id,kind,message,expected_fingerprint,observed_fingerprint,created_at) VALUES(1,'changed','Terzo certificato','EXPECTED','THIRD',2100000002)");
    REQUIRE(delivery_queue_monitor_event(&s,3,now+2,&queued,error,sizeof error)&&queued==4);
    REQUIRE(scalar(&s,"SELECT count(*) FROM outbox WHERE event_id=3 AND recipient_email='anna@example.test' AND template_copy=1 AND template_audience='self' AND subject='SELF changed'")==1);
    free(api(&s,"PUT","/api/mail-templates/settings","self_name=Me&self_email=me%40example.test",200));
    sql(&s,"INSERT INTO notifications VALUES(1,30,2100000000); INSERT INTO reminder_policies(certificate_id,thresholds,escalation_name,escalation_email,escalation_after_days,enabled) VALUES(1,'45,30,15,2,0','Ops','ops@example.test',0,1)");
    free(api(&s,"PUT","/api/mail-templates/template","alert=escalation&audience=self&subject=Escalation+owner&body=Owner+copy&copy_enabled=1",200));free(api(&s,"PUT","/api/mail-templates/template","alert=escalation&audience=business&subject=Escalation+business&body=Business+copy&copy_enabled=1",200));
    REQUIRE(reminder_policy_check_escalation(&s,1,now,&queued,error,sizeof error)&&queued==3);REQUIRE(scalar(&s,"SELECT count(*) FROM outbox WHERE kind='escalation' AND template_copy=1")==2);REQUIRE(scalar(&s,"SELECT count(*) FROM outbox WHERE kind='escalation' AND template_audience='other' AND template_copy=0")==1);sql(&s,"UPDATE reminder_policies SET enabled=0");REQUIRE(delivery_process(&s,now+3,&sent,error,sizeof error));REQUIRE(scalar(&s,"SELECT count(*) FROM outbox WHERE kind='escalation'")==0);store_close(&s);
}
static void expanded_limit_template(Store *s,const char *alert,const char *audience){
    char form[3000];snprintf(form,sizeof form,"alert=%s&audience=%s&subject=",alert,audience);
    /* 65 × 15 source bytes fit 998, but 65 × 16 CN bytes expand beyond it. */
    for(int i=0;i<65;i++)strcat(form,"%7B%7Bcommon_name%7D%7D");
    strcat(form,"&body=Test&copy_enabled=0");free(api(s,"PUT","/api/mail-templates/template",form,200));
}
static void test_dedup_before_render(char *pem){
    Store s;setup(&s,pem);int queued=0;
    REQUIRE(delivery_queue_expiry(&s,1,30,now,error,sizeof error));
    REQUIRE(delivery_queue_certificate(&s,1,pem,now,&queued,error,sizeof error)&&queued==1);
    sql(&s,"INSERT INTO monitors(certificate_id,target,email_alerts,created_at,updated_at) VALUES(1,'https://service.example.test:443',1,2100000000,2100000000); INSERT INTO monitor_recipients VALUES(1,'Ops','ops@example.test'); INSERT INTO monitor_events(monitor_id,kind,message,expected_fingerprint,observed_fingerprint,created_at) VALUES(1,'changed','Changed','EXPECTED','OBSERVED',2100000000); INSERT INTO notifications VALUES(1,30,2100000000); INSERT INTO reminder_policies(certificate_id,thresholds,escalation_name,escalation_email,escalation_after_days,enabled) VALUES(1,'45,30,15,2,0','Ops','ops@example.test',0,1)");
    REQUIRE(delivery_queue_monitor_event(&s,1,now,&queued,error,sizeof error)&&queued==1);
    REQUIRE(reminder_policy_check_escalation(&s,1,now,&queued,error,sizeof error)&&queued==1);
    expanded_limit_template(&s,"expiry_30","business");expanded_limit_template(&s,"expiry_45","business");expanded_limit_template(&s,"expiry_15","business");expanded_limit_template(&s,"certificate","technical");expanded_limit_template(&s,"changed","other");expanded_limit_template(&s,"escalation","other");
    char *snapshot=text_scalar(&s,"SELECT group_concat(subject,'|') FROM (SELECT subject FROM outbox ORDER BY id)");
    REQUIRE(delivery_queue_expiry(&s,1,30,now,error,sizeof error));
    REQUIRE(delivery_queue_expiry(&s,1,45,now,error,sizeof error));
    REQUIRE(delivery_queue_certificate(&s,1,pem,now,&queued,error,sizeof error)&&queued==0);
    REQUIRE(delivery_queue_monitor_event(&s,1,now,&queued,error,sizeof error)&&queued==0);
    REQUIRE(reminder_policy_check_escalation(&s,1,now,&queued,error,sizeof error)&&queued==0);
    char *unchanged=text_scalar(&s,"SELECT group_concat(subject,'|') FROM (SELECT subject FROM outbox ORDER BY id)");REQUIRE(!strcmp(snapshot,unchanged));free(unchanged);free(snapshot);REQUIRE(scalar(&s,"SELECT count(*) FROM outbox")==4);
    /* Skipping a duplicate must not run pruning on other pending snapshots. */
    sql(&s,"INSERT INTO outbox(certificate_id,kind,recipient_name,recipient_email,threshold,subject,body,created_at) VALUES(1,'expiry','Anna','anna@example.test',45,'Legacy snapshot','Existing',2100000000)");
    REQUIRE(delivery_queue_expiry(&s,1,30,now,error,sizeof error));REQUIRE(scalar(&s,"SELECT count(*) FROM outbox WHERE kind='expiry' AND threshold=45")==1);
    /* A genuinely new, invalid expansion fails explicitly before pruning any
     * earlier reminders; the caller retains a fully atomic decision. */
    REQUIRE(!delivery_queue_expiry(&s,1,15,now,error,sizeof error));REQUIRE(strstr(error,"lunghezza"));REQUIRE(scalar(&s,"SELECT count(*) FROM outbox")==5);REQUIRE(sqlite3_get_autocommit(s.db));store_close(&s);
}
int main(void){char *pem=public_pem();Store s;setup(&s,pem);test_render_and_validation(&s);test_snapshot_and_copy_controls(&s,pem);test_monitor_and_escalation(pem);test_dedup_before_render(pem);char *state=api(&s,"GET","/api/mail-templates/state","",200);REQUIRE(strstr(state,"\"variables\":[")&&strstr(state,"\"customized\":true"));free(state);store_close(&s);free(pem);puts("Template email: rendering, validazione, snapshot e copie PASS");return 0;}
