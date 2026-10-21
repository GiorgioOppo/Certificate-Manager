#include "app.h"
#include "incident.h"
#include "monitor.h"
#include "delivery.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static char error[1024];
static int64_t scalar(Store *s,const char *sql){sqlite3_stmt *q=NULL;assert(sqlite3_prepare_v2(s->db,sql,-1,&q,NULL)==SQLITE_OK);assert(sqlite3_step(q)==SQLITE_ROW);int64_t v=sqlite3_column_int64(q,0);sqlite3_finalize(q);return v;}
static void execute(Store *s,const char *sql){assert(store_exec(s,sql,error,sizeof error));}
static int64_t revision(Store *s){return scalar(s,"SELECT revision FROM monitors WHERE id=1");}
static void api(Store *s,const char *path,const char *body,int expected){size_t length=0;int status=0;char *json=incident_api(s,"POST",path,(const unsigned char*)body,strlen(body),&length,&status,error,sizeof error);if(status!=expected)fprintf(stderr,"API status=%d expected=%d: %s\n",status,expected,error);assert(status==expected);if(expected==200)assert(json&&length&&strstr(json,"true"));else assert(!json);free(json);}
static void record(Store *s,int64_t now,const char *fingerprint,int reachable,int verified){Certificate certificate={0};certificate.fingerprint=(char*)fingerprint;RemoteResult remote={0};remote.dns_ok=remote.tcp_ok=remote.tls_ok=reachable;remote.verified=verified;remote.certificates.items=&certificate;remote.certificates.count=reachable?1:0;assert(monitor_record_result(s,1,revision(s),now,&remote,0,NULL,error,sizeof error));}
static void busy_reader_regression(const Certificate *certificate,int64_t now){
    char path[]="/tmp/certificati-incident-busy-XXXXXX";int fd=mkstemp(path);assert(fd>=0);close(fd);
    Store s={0};assert(store_open(&s,path,error,sizeof error));int64_t id=0,monitor=0;int inserted=0;
    assert(store_add(&s,certificate,"lock regression",now,&id,&inserted,error,sizeof error));
    assert(monitor_save(&s,0,id,"https://localhost:443",900,1,now,&monitor,error,sizeof error));
    execute(&s,"INSERT INTO monitor_options(monitor_id,maintenance_start,maintenance_end,maintenance_processed) VALUES(1,1,2,0)");
    sqlite3 *reader=NULL;assert(sqlite3_open(path,&reader)==SQLITE_OK);assert(sqlite3_exec(reader,"BEGIN",NULL,NULL,NULL)==SQLITE_OK);
    sqlite3_stmt *read=NULL;assert(sqlite3_prepare_v2(reader,"SELECT * FROM monitors",-1,&read,NULL)==SQLITE_OK);assert(sqlite3_step(read)==SQLITE_ROW);
    sqlite3_busy_timeout(s.db,0);
    assert(!incident_tick(&s,now,error,sizeof error));assert(sqlite3_get_autocommit(s.db));
    assert(!incident_record(&s,1,now,"unreachable","ok",certificate->fingerprint,"","","forced test",error,sizeof error));assert(sqlite3_get_autocommit(s.db));
    api(&s,"/api/incidents/monitor-options","monitor_id=1&failure_threshold=2",400);assert(sqlite3_get_autocommit(s.db));
    sqlite3_finalize(read);assert(sqlite3_exec(reader,"ROLLBACK",NULL,NULL,NULL)==SQLITE_OK);sqlite3_close(reader);
    assert(!scalar(&s,"SELECT count(*) FROM monitor_events"));assert(scalar(&s,"SELECT failure_threshold FROM monitor_options WHERE monitor_id=1")==1);
    assert(incident_tick(&s,now,error,sizeof error));assert(sqlite3_get_autocommit(s.db));
    /* The scheduler runs with a zero busy timeout. A reader must not leave its
       failed claim or result savepoint holding a PENDING database lock. */
    assert(sqlite3_open(path,&reader)==SQLITE_OK);assert(sqlite3_exec(reader,"BEGIN",NULL,NULL,NULL)==SQLITE_OK);
    assert(sqlite3_prepare_v2(reader,"SELECT * FROM monitors",-1,&read,NULL)==SQLITE_OK);assert(sqlite3_step(read)==SQLITE_ROW);
    assert(!monitor_tick(&s,now,error,sizeof error));assert(sqlite3_get_autocommit(s.db));
    Certificate observed={0};observed.fingerprint=certificate->fingerprint;RemoteResult result={0};result.dns_ok=result.tcp_ok=result.tls_ok=result.verified=1;result.certificates.items=&observed;result.certificates.count=1;
    assert(!monitor_record_result(&s,1,revision(&s),now,&result,0,NULL,error,sizeof error));assert(sqlite3_get_autocommit(s.db));
    assert(!monitor_save(&s,1,id,"https://localhost:443",900,0,now,&monitor,error,sizeof error));assert(sqlite3_get_autocommit(s.db));
    sqlite3_finalize(read);assert(sqlite3_exec(reader,"ROLLBACK",NULL,NULL,NULL)==SQLITE_OK);sqlite3_close(reader);
    assert(scalar(&s,"SELECT last_checked_at IS NULL FROM monitors WHERE id=1"));assert(scalar(&s,"SELECT enabled FROM monitors WHERE id=1"));
    execute(&s,"UPDATE monitors SET enabled=0");store_close(&s);unlink(path);
}
int main(void){
    Store s={0};assert(store_open(&s,":memory:",error,sizeof error));int64_t now=(int64_t)time(NULL);Certificate cert={0};
    const char *expected="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const char *foreign="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    cert.fingerprint=(char*)expected;cert.common_name="localhost";cert.subject="CN=localhost";cert.issuer="CN=Test CA";cert.serial="01";cert.sans="DNS:localhost";cert.key_algorithm="RSA";cert.key_bits=2048;cert.signature_algorithm="SHA256";cert.not_before=now-60;cert.not_after=now+86400;int inserted=0;int64_t id=0;
    assert(store_add(&s,&cert,"incidents test",now,&id,&inserted,error,sizeof error));int64_t monitor=0;assert(monitor_save(&s,0,id,"https://localhost:443",900,1,now,&monitor,error,sizeof error));assert(monitor==1);
    execute(&s,"UPDATE monitors SET email_alerts=1; INSERT INTO monitor_recipients(monitor_id,name,email) VALUES(1,'Test','ops@example.test');");
    api(&s,"/api/incidents/monitor-options","monitor_id=1&failure_threshold=3",200);
    record(&s,now,expected,1,1);record(&s,now+1,expected,0,0);
    assert(scalar(&s,"SELECT count(*) FROM monitor_events WHERE kind='unreachable'")==1);
    assert(scalar(&s,"SELECT last_status='unreachable' FROM monitors WHERE id=1"));assert(!scalar(&s,"SELECT count(*) FROM outbox"));
    record(&s,now+2,expected,1,1);assert(!scalar(&s,"SELECT count(*) FROM monitor_events WHERE kind='recovered'"));
    record(&s,now+3,expected,0,0);record(&s,now+4,expected,0,0);assert(!scalar(&s,"SELECT count(*) FROM outbox"));record(&s,now+5,expected,0,0);assert(scalar(&s,"SELECT count(*) FROM outbox")==1);record(&s,now+6,expected,0,0);assert(scalar(&s,"SELECT count(*) FROM outbox")==1);
    api(&s,"/api/incidents/events/2/claim","responsible=Operator&notes=Working&status=resolved&due_at=0",200);
    assert(scalar(&s,"SELECT last_status='unreachable' FROM monitors WHERE id=1"));assert(scalar(&s,"SELECT incident_open FROM monitor_options WHERE monitor_id=1"));assert(!scalar(&s,"SELECT count(*) FROM monitor_events WHERE kind='recovered'"));assert(!scalar(&s,"SELECT acknowledged_at IS NOT NULL FROM monitor_events WHERE id=2"));
    record(&s,now+7,expected,1,1);assert(scalar(&s,"SELECT count(*) FROM monitor_events WHERE kind='recovered'")==1);assert(scalar(&s,"SELECT count(*) FROM outbox")==2);
    assert(scalar(&s,"SELECT count(*) FROM outbox o JOIN monitor_events e ON e.id=o.event_id WHERE e.kind='unreachable'")==1);
    assert(scalar(&s,"SELECT count(*) FROM outbox o JOIN monitor_events e ON e.id=o.event_id WHERE e.kind='recovered'")==1);
    /* Unknown fingerprints do not wait for the DNS/TCP confirmation threshold. */
    record(&s,now+8,foreign,1,1);assert(scalar(&s,"SELECT count(*) FROM outbox")==3);assert(scalar(&s,"SELECT last_status='changed' FROM monitors WHERE id=1"));
    char body[256];snprintf(body,sizeof body,"monitor_id=1&failure_threshold=3&maintenance_start=%lld&maintenance_end=%lld&maintenance_reason=Upgrade",(long long)(now-1),(long long)(now+100));api(&s,"/api/incidents/monitor-options",body,200);
    assert(setenv("CERTIFICATI_SMTP_URL","smtp://127.0.0.1:1",1)==0);
    assert(setenv("CERTIFICATI_SMTP_FROM","sender@example.test",1)==0);
    int sent=99;assert(delivery_process(&s,now+9,&sent,error,sizeof error));assert(sent==0);
    assert(scalar(&s,"SELECT count(*) FROM outbox")==3);assert(!scalar(&s,"SELECT sum(attempts) FROM outbox"));
    assert(unsetenv("CERTIFICATI_SMTP_URL")==0);assert(unsetenv("CERTIFICATI_SMTP_FROM")==0);
    record(&s,now+10,expected,1,1);record(&s,now+11,foreign,1,1);assert(scalar(&s,"SELECT count(*) FROM outbox")==3);assert(scalar(&s,"SELECT last_status='changed' FROM monitors WHERE id=1"));
    int64_t old_revision=revision(&s);assert(incident_tick(&s,now+100,error,sizeof error));assert(revision(&s)>old_revision);assert(scalar(&s,"SELECT post_maintenance_check FROM monitor_options WHERE monitor_id=1"));
    Certificate observed={0};observed.fingerprint=(char*)expected;RemoteResult remote={0};remote.dns_ok=remote.tcp_ok=remote.tls_ok=remote.verified=1;remote.certificates.items=&observed;remote.certificates.count=1;
    assert(monitor_record_result(&s,1,old_revision,now+101,&remote,0,NULL,error,sizeof error));assert(scalar(&s,"SELECT last_status='changed' FROM monitors WHERE id=1"));
    record(&s,now+101,foreign,1,1);assert(scalar(&s,"SELECT count(*) FROM outbox")==4);int64_t events=scalar(&s,"SELECT count(*) FROM monitor_events");record(&s,now+102,foreign,1,1);assert(scalar(&s,"SELECT count(*) FROM outbox")==4);assert(scalar(&s,"SELECT count(*) FROM monitor_events")==events);assert(!scalar(&s,"SELECT post_maintenance_check FROM monitor_options WHERE monitor_id=1"));
    assert(scalar(&s,"SELECT count(DISTINCT event_id) FROM outbox")==4);
    assert(scalar(&s,"SELECT count(*) FROM outbox o JOIN monitor_events e ON e.id=o.event_id WHERE e.kind='changed'")==2);
    assert(scalar(&s,"SELECT count(*) FROM outbox o JOIN monitor_events e ON e.id=o.event_id WHERE e.kind='recovered'")==1);
    assert(scalar(&s,"SELECT count(*) FROM outbox o JOIN monitor_events e ON e.id=o.event_id WHERE e.kind='unreachable'")==1);
    api(&s,"/api/incidents/monitor-options","monitor_id=1&failure_threshold=11",400);api(&s,"/api/incidents/monitor-options","monitor_id=1&failure_threshold=2&failure_threshold=3",400);api(&s,"/api/incidents/events/1/claim","responsible=Operator&status=ok",400);api(&s,"/api/incidents/events/999/claim","responsible=Operator&status=open",400);
    /* A new endpoint starts its own failure series and cannot send the old
       endpoint's still-pending anomaly email. */
    assert(monitor_save(&s,1,id,"https://localhost:444",900,1,now+103,&monitor,error,sizeof error));
    assert(!scalar(&s,"SELECT count(*) FROM outbox"));assert(!scalar(&s,"SELECT incident_open FROM monitor_options WHERE monitor_id=1"));
    record(&s,now+104,expected,0,0);assert(!scalar(&s,"SELECT count(*) FROM outbox"));assert(scalar(&s,"SELECT consecutive_failures FROM monitor_options WHERE monitor_id=1")==1);
    assert(scalar(&s,"SELECT count(*) FROM workflow_audit WHERE entity_type='monitor_event'")>=5);assert(!scalar(&s,"SELECT count(*) FROM pragma_foreign_key_check"));
    store_close(&s);busy_reader_regression(&cert,now);puts("Test incidenti, manutenzione e conferma guasti: OK");return 0;
}
