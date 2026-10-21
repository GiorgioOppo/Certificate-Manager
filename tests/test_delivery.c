#define _POSIX_C_SOURCE 200809L
#include "delivery.h"

#include <arpa/inet.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define REQUIRE(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s; dettaglio: %s\n", __FILE__, __LINE__, #condition, error); \
    exit(EXIT_FAILURE); } } while (0)

static char error[512];
static const int64_t now = INT64_C(2100000000);
static char *pem;

static void no_configuration(void)
{
    REQUIRE(unsetenv("CERTIFICATI_SMTP_URL") == 0);
    REQUIRE(unsetenv("CERTIFICATI_SMTP_FROM") == 0);
    REQUIRE(unsetenv("CERTIFICATI_SMTP_USERNAME") == 0);
    REQUIRE(unsetenv("CERTIFICATI_SMTP_PASSWORD") == 0);
    REQUIRE(unsetenv("CERTIFICATI_SMTP_CA_FILE") == 0);
}

static int scalar(Store *store, const char *sql)
{
    sqlite3_stmt *stmt = NULL;
    REQUIRE(sqlite3_prepare_v2(store->db, sql, -1, &stmt, NULL) == SQLITE_OK);
    REQUIRE(sqlite3_step(stmt) == SQLITE_ROW);
    int result = sqlite3_column_int(stmt, 0);
    REQUIRE(sqlite3_finalize(stmt) == SQLITE_OK);
    return result;
}

static void sql(Store *store, const char *command)
{
    REQUIRE(store_exec(store, command, error, sizeof error));
}

static void setup(Store *store)
{
    no_configuration();
    REQUIRE(store_open(store, ":memory:", error, sizeof error));
    Certificate cert = {
        .common_name = "www.example.test", .subject = "CN=www.example.test",
        .issuer = "CN=Example CA", .serial = "1234", .sans = "DNS:www.example.test",
        .fingerprint = "delivery-test-fingerprint", .key_algorithm = "RSA",
        .signature_algorithm = "sha256WithRSAEncryption", .key_bits = 2048,
        .not_before = now - 86400, .not_after = now + 30 * 86400,
        .pem = pem
    };
    int64_t id;
    int inserted;
    REQUIRE(store_add(store, &cert, "test.pem", now, &id, &inserted, error, sizeof error));
    REQUIRE(inserted && id == 1);
}

static void generate_public_certificate(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;
    REQUIRE(ctx && EVP_PKEY_keygen_init(ctx) > 0);
    REQUIRE(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) > 0);
    REQUIRE(EVP_PKEY_keygen(ctx, &key) > 0);
    EVP_PKEY_CTX_free(ctx);
    X509 *cert = X509_new();
    REQUIRE(cert);
    REQUIRE(X509_set_version(cert, 2));
    REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1));
    REQUIRE(X509_gmtime_adj(X509_getm_notBefore(cert), 0));
    REQUIRE(X509_gmtime_adj(X509_getm_notAfter(cert), 86400));
    REQUIRE(X509_set_pubkey(cert, key));
    X509_NAME *name = X509_NAME_new();
    REQUIRE(name && X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char *)"www.example.test", -1, -1, 0));
    REQUIRE(X509_set_subject_name(cert, name));
    REQUIRE(X509_set_issuer_name(cert, name));
    X509_NAME_free(name);
    REQUIRE(X509_sign(cert, key, EVP_sha256()) > 0);
    BIO *bio = BIO_new(BIO_s_mem());
    REQUIRE(bio && PEM_write_bio_X509(bio, cert));
    char *data = NULL;
    long length = BIO_get_mem_data(bio, &data);
    REQUIRE(length > 0);
    pem = strndup(data, (size_t)length);
    REQUIRE(pem);
    BIO_free(bio); X509_free(cert); EVP_PKEY_free(key);
}

static void test_expiry_queue_and_obsolete_thresholds(void)
{
    Store store;
    setup(&store);
    sql(&store, "INSERT INTO contacts VALUES(1,'business','Màrio Rossi','business1@example.test');"
        "INSERT INTO contacts VALUES(1,'business','Anna Bianchi','business2@example.test');"
        "INSERT INTO contacts VALUES(1,'technical','Tecnico','tech@example.test')");
    REQUIRE(delivery_queue_expiry(&store, 1, 45, now, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 2);
    sql(&store, "UPDATE contacts SET email='BUSINESS2@EXAMPLE.TEST' WHERE email='business2@example.test'");
    REQUIRE(delivery_queue_expiry(&store, 1, 45, now, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 2);
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox WHERE kind='expiry' AND threshold=45 AND status='pending'") == 2);
    REQUIRE(delivery_queue_expiry(&store, 1, 45, now, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 2);
    sql(&store, "UPDATE outbox SET status='sent',sent_at=2100000000 WHERE recipient_email='business1@example.test'");
    REQUIRE(delivery_queue_expiry(&store, 1, 30, now, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 3);
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox WHERE threshold=45 AND status='sent'") == 1);
    REQUIRE(delivery_queue_expiry(&store, 1, 15, now, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox WHERE threshold=30") == 0);
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox WHERE threshold=15") == 2);
    REQUIRE(delivery_queue_expiry(&store, 1, 45, now, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 3);
    REQUIRE(!delivery_queue_expiry(&store, 1, -1, now, error, sizeof error));
    REQUIRE(!delivery_queue_expiry(&store, 1, 3651, now, error, sizeof error));
    int sent = -1;
    REQUIRE(!delivery_is_configured(&store));
    REQUIRE(delivery_process(&store, now, &sent, error, sizeof error) && sent == 0);
    REQUIRE(scalar(&store, "SELECT sum(attempts) FROM outbox") == 0);
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox WHERE status='pending'") == 2);
    store_close(&store);
}

static char *decode_body(const char *message, size_t *decoded_length)
{
    const char *start = strstr(message, "\r\n\r\n");
    REQUIRE(start);
    start += 4;
    const char *end = strstr(start, "\r\n--");
    size_t length = end ? (size_t)(end - start) : strlen(start);
    char *compact = malloc(length + 1);
    REQUIRE(compact);
    size_t compact_length = 0;
    for (size_t i = 0; i < length; ++i)
        if (start[i] != '\r' && start[i] != '\n') compact[compact_length++] = start[i];
    compact[compact_length] = 0;
    unsigned char *decoded = malloc(compact_length + 1);
    REQUIRE(decoded);
    int result = EVP_DecodeBlock(decoded, (const unsigned char *)compact, (int)compact_length);
    REQUIRE(result >= 0);
    while (compact_length && compact[compact_length - 1] == '=') { --result; --compact_length; }
    decoded[result] = 0;
    if (decoded_length) *decoded_length = (size_t)result;
    free(compact);
    return (char *)decoded;
}

static void test_custom_reminders_and_escalation(void)
{
    Store store;
    setup(&store);
    int threshold = -2, queued = -1, sent = -1;
    int64_t expiry = now + INT64_C(30) * 86400;
    REQUIRE(reminder_policy_due(&store, 1, expiry, now, &threshold, error, sizeof error));
    REQUIRE(threshold == 30);
    sql(&store, "INSERT INTO reminder_policies(certificate_id,thresholds,escalation_email,"
        "escalation_name,escalation_after_days) VALUES(1,'60,21,7,0','manager@example.test','Responsabile',2)");
    REQUIRE(reminder_policy_due(&store, 1, expiry, now, &threshold, error, sizeof error));
    REQUIRE(threshold == 60);
    REQUIRE(reminder_policy_due(&store, 1, expiry, expiry-21*86400-1, &threshold, error, sizeof error));
    REQUIRE(threshold == 60);
    REQUIRE(reminder_policy_due(&store, 1, expiry, expiry-21*86400, &threshold, error, sizeof error));
    REQUIRE(threshold == 21);
    REQUIRE(reminder_policy_due(&store, 1, expiry, expiry+1, &threshold, error, sizeof error));
    REQUIRE(threshold == 0);
    REQUIRE(reminder_policy_check_escalation(&store, 1, now, &queued, error, sizeof error) && queued == 0);
    sql(&store, "INSERT INTO notifications VALUES(1,60,2100000000)");
    REQUIRE(reminder_policy_check_escalation(&store, 1, now+2*86400-1, &queued, error, sizeof error) && queued == 0);
    REQUIRE(reminder_policy_check_escalation(&store, 1, now+2*86400, &queued, error, sizeof error) && queued == 1);
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox WHERE kind='escalation' AND event_id IS NULL") == 1);
    /* Escalation destinations are deliberately independent of certificate roles. */
    REQUIRE(delivery_process(&store, now+2*86400, &sent, error, sizeof error) && sent == 0);
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 1);
    REQUIRE(scalar(&store, "SELECT attempts FROM outbox") == 0);
    sql(&store, "UPDATE outbox SET status='sent',sent_at=2100172800;"
        "UPDATE reminder_policies SET escalation_email='MANAGER@EXAMPLE.TEST'");
    REQUIRE(reminder_policy_check_escalation(&store, 1, now+3*86400, &queued, error, sizeof error) && queued == 0);
    sql(&store, "UPDATE reminder_policies SET enabled=0");
    REQUIRE(reminder_policy_due(&store, 1, expiry, now, &threshold, error, sizeof error) && threshold == -1);
    REQUIRE(reminder_policy_check_escalation(&store, 1, now+3*86400, &queued, error, sizeof error) && queued == 0);
    sql(&store, "UPDATE reminder_policies SET enabled=1,thresholds='21,7,0';"
        "INSERT INTO contacts VALUES(1,'business','Referente','business@example.test')");
    REQUIRE(delivery_queue_expiry(&store, 1, 21, now, error, sizeof error));
    REQUIRE(delivery_queue_expiry(&store, 1, 7, now, error, sizeof error));
    REQUIRE(delivery_queue_expiry(&store, 1, 21, now, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox WHERE kind='expiry' AND threshold=21") == 0);
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox WHERE kind='expiry' AND threshold=7") == 1);
    const char *bad[] = {"", "21,7", "21,7,7,0", "3651,0", "-1,0", "7,0,", "7,x,0", "7,0, "};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; ++i) {
        sqlite3_stmt *stmt = NULL;
        REQUIRE(sqlite3_prepare_v2(store.db, "UPDATE reminder_policies SET thresholds=?", -1, &stmt, NULL) == SQLITE_OK);
        REQUIRE(sqlite3_bind_text(stmt, 1, bad[i], -1, SQLITE_STATIC) == SQLITE_OK);
        REQUIRE(sqlite3_step(stmt) == SQLITE_DONE);
        REQUIRE(sqlite3_finalize(stmt) == SQLITE_OK);
        REQUIRE(!reminder_policy_due(&store, 1, expiry, now, &threshold, error, sizeof error));
    }
    /* Pausing rules also removes unsent expiry mail; historical sends stay. */
    sql(&store, "UPDATE reminder_policies SET enabled=0,thresholds='45,30,15,2,0'");
    REQUIRE(delivery_process(&store, now+3*86400, &sent, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox WHERE kind='expiry'") == 0);
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox WHERE status='sent'") == 1);
    store_close(&store);
}

static void test_monitor_event_queue_recipients_and_recovery(void)
{
    Store store;
    setup(&store);
    sql(&store, "INSERT INTO monitors(certificate_id,target,created_at,updated_at) "
        "VALUES(1,'https://www.example.test',2100000000,2100000000);"
        "INSERT INTO monitor_recipients VALUES(1,'Responsabile','owner@example.test');"
        "INSERT INTO monitor_recipients VALUES(1,'Tecnico','tech@example.test');"
        "INSERT INTO monitor_events(monitor_id,kind,message,expected_fingerprint,observed_fingerprint,created_at) "
        "VALUES(1,'changed','Certificato inatteso','AA:BB','CC:DD',2100000000)");
    int queued = -1, sent = -1;
    REQUIRE(delivery_queue_monitor_event(&store, 1, now, &queued, error, sizeof error) && queued == 0);
    sql(&store, "UPDATE monitors SET email_alerts=1");
    REQUIRE(delivery_queue_monitor_event(&store, 1, now, &queued, error, sizeof error) && queued == 2);
    sql(&store, "UPDATE monitor_recipients SET email='OWNER@EXAMPLE.TEST' WHERE email='owner@example.test'");
    REQUIRE(delivery_queue_monitor_event(&store, 1, now, &queued, error, sizeof error) && queued == 0);
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox WHERE kind='monitor' AND event_id=1") == 2);
    size_t length = 0;
    char *message = delivery_message(&store, scalar(&store, "SELECT min(id) FROM outbox"), &length, error, sizeof error);
    REQUIRE(message && length == strlen(message));
    char *body = decode_body(message, NULL);
    REQUIRE(strstr(body, "https://www.example.test") && strstr(body, "AA:BB") && strstr(body, "CC:DD"));
    REQUIRE(!strstr(message, "application/x-pem-file"));
    free(body); free(message);
    sql(&store, "INSERT INTO monitor_events(monitor_id,kind,message,expected_fingerprint,observed_fingerprint,created_at) "
        "VALUES(1,'recovered','Servizio ripristinato','AA:BB','AA:BB',2100000001)");
    REQUIRE(delivery_queue_monitor_event(&store, 2, now+1, &queued, error, sizeof error) && queued == 2);
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox WHERE kind='monitor'") == 4);
    REQUIRE(delivery_process(&store, now+1, &sent, error, sizeof error) && sent == 0);
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 4);
    REQUIRE(scalar(&store, "SELECT sum(attempts) FROM outbox") == 0);
    sql(&store, "UPDATE outbox SET status='sent',sent_at=2100000001 WHERE id=1;"
        "DELETE FROM monitor_recipients WHERE email='tech@example.test'");
    REQUIRE(delivery_process(&store, now+2, &sent, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 2);
    sql(&store, "UPDATE monitors SET email_alerts=0");
    REQUIRE(delivery_process(&store, now+3, &sent, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 1);
    REQUIRE(scalar(&store, "SELECT status='sent' FROM outbox"));
    sql(&store, "UPDATE monitors SET email_alerts=1;"
        "INSERT INTO monitor_recipients VALUES(1,'Invalid'||char(13)||char(10)||'Bcc: leak','bad@example.test')");
    REQUIRE(!delivery_queue_monitor_event(&store, 2, now+4, &queued, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 1);
    store_close(&store);
}

static void test_notification_claims_recheck_configuration(void)
{
    Store store;
    setup(&store);
    sql(&store, "INSERT INTO reminder_policies(certificate_id,escalation_email,escalation_after_days) "
        "VALUES(1,'manager@example.test',0);INSERT INTO notifications VALUES(1,30,2100000000);"
        "INSERT INTO monitors(certificate_id,target,email_alerts,created_at,updated_at) "
        "VALUES(1,'https://www.example.test',1,2100000000,2100000000);"
        "INSERT INTO monitor_recipients VALUES(1,'Tecnico','monitor@example.test');"
        "INSERT INTO monitor_events(monitor_id,kind,message,expected_fingerprint,created_at) "
        "VALUES(1,'unreachable','Servizio non raggiungibile','AA:BB',2100000000)");
    int queued = -1, sent = -1;
    REQUIRE(reminder_policy_check_escalation(&store, 1, now, &queued, error, sizeof error) && queued == 1);
    REQUIRE(reminder_policy_check_escalation(&store, 1, now, &queued, error, sizeof error) && queued == 0);
    REQUIRE(delivery_queue_monitor_event(&store, 1, now, &queued, error, sizeof error) && queued == 1);
    REQUIRE(setenv("CERTIFICATI_SMTP_URL", "smtp://127.0.0.1:1", 1) == 0);
    REQUIRE(setenv("CERTIFICATI_SMTP_FROM", "sender@example.test", 1) == 0);
    /* Invalid headers fail before libcurl starts any SMTP connection. This
     * checks claim eligibility and retry state for both new message kinds. */
    sql(&store, "UPDATE outbox SET subject='Invalid'||char(10)||'Bcc: blocked'");
    REQUIRE(!delivery_process(&store, now, &sent, error, sizeof error) && sent == 0);
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox WHERE status='failed' AND attempts=1") == 2);
    no_configuration();
    sql(&store, "UPDATE reminder_policies SET enabled=0;UPDATE monitors SET email_alerts=0");
    REQUIRE(delivery_process(&store, now+1, &sent, error, sizeof error) && sent == 0);
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 0);
    store_close(&store);
}

static void test_attachment_preview_and_privacy(void)
{
    Store store;
    setup(&store);
    int queued = -1;
    REQUIRE(!delivery_queue_certificate(&store, 1, pem, now, &queued, error, sizeof error));
    REQUIRE(queued == 0 && strstr(error, "referente tecnico"));
    sql(&store, "INSERT INTO contacts VALUES(1,'technical','Tècnico con un nome abbastanza lungo da richiedere ripiegamento intestazione UTF-8','tech1@example.test');"
        "INSERT INTO contacts VALUES(1,'technical','Secondo tecnico','tech2@example.test')");
    REQUIRE(delivery_queue_certificate(&store, 1, pem, now, &queued, error, sizeof error) && queued == 2);
    sql(&store, "UPDATE contacts SET email='TECH1@EXAMPLE.TEST' WHERE email='tech1@example.test'");
    REQUIRE(delivery_queue_certificate(&store, 1, pem, now, &queued, error, sizeof error) && queued == 0);
    int64_t id = scalar(&store, "SELECT id FROM outbox WHERE recipient_email='tech1@example.test'");
    size_t length = 0;
    char *message = delivery_message(&store, id, &length, error, sizeof error);
    REQUIRE(message && length == strlen(message));
    REQUIRE(strstr(message, "From: <certificati@localhost.invalid>\r\n"));
    REQUIRE(strstr(message, "<tech1@example.test>\r\n"));
    REQUIRE(!strstr(message, "tech2@example.test"));
    REQUIRE(strstr(message, "Subject: =?UTF-8?B?"));
    REQUIRE(strstr(message, "\r\n =?UTF-8?B?"));
    REQUIRE(strstr(message, "Content-Type: multipart/mixed;"));
    REQUIRE(strstr(message, "filename=\"certificate.pem\""));
    for (size_t i = 0; i < length; ++i) {
        if (message[i] == '\n') REQUIRE(i > 0 && message[i - 1] == '\r');
        if (message[i] == '\r') REQUIRE(i + 1 < length && message[i + 1] == '\n');
    }
    const char *part = strstr(message, "Content-Type: text/plain;");
    REQUIRE(part);
    char *body = decode_body(part, NULL);
    REQUIRE(strstr(body, "firmato per www.example.test"));
    REQUIRE(strstr(body, "\r\n"));
    free(body);
    part = strstr(message, "Content-Type: application/x-pem-file;");
    REQUIRE(part);
    size_t decoded_length;
    char *attachment = decode_body(part, &decoded_length);
    REQUIRE(decoded_length == strlen(pem) && !memcmp(attachment, pem, decoded_length));
    free(attachment);
    char *again = delivery_message(&store, id, &length, error, sizeof error);
    REQUIRE(again && !strcmp(message, again));
    free(again); free(message);
    REQUIRE(!delivery_queue_certificate(&store, 1, "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n", now, &queued, error, sizeof error));
    REQUIRE(!delivery_queue_certificate(&store, 1, "not a certificate", now, &queued, error, sizeof error));
    store_close(&store);
}

static void test_header_injection_and_transaction_rollback(void)
{
    Store store;
    setup(&store);
    sql(&store, "INSERT INTO contacts VALUES(1,'business','Valid','valid@example.test');"
        "INSERT INTO contacts VALUES(1,'business','Injected'||char(13)||char(10)||'Bcc: bad@example.test','zbad@example.test')");
    REQUIRE(!delivery_queue_expiry(&store, 1, 30, now, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 0);
    sql(&store, "DELETE FROM contacts WHERE email='zbad@example.test';"
        "INSERT INTO contacts VALUES(1,'business','Bad email','two@example.test,three@example.test')");
    REQUIRE(!delivery_queue_expiry(&store, 1, 30, now, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 0);
    sql(&store, "DELETE FROM contacts WHERE email<>'valid@example.test';BEGIN IMMEDIATE");
    REQUIRE(delivery_queue_expiry(&store, 1, 30, now, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 1);
    int sent;
    REQUIRE(!delivery_process(&store, now, &sent, error, sizeof error));
    sql(&store, "ROLLBACK");
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 0);
    store_close(&store);
}

static void test_configuration_retries_and_leases(void)
{
    Store store;
    setup(&store);
    sql(&store, "INSERT INTO contacts VALUES(1,'business','Business','business@example.test')");
    REQUIRE(delivery_queue_expiry(&store, 1, 30, now, error, sizeof error));
    REQUIRE(setenv("CERTIFICATI_SMTP_URL", "https://example.test", 1) == 0);
    REQUIRE(setenv("CERTIFICATI_SMTP_FROM", "sender@example.test", 1) == 0);
    int sent;
    REQUIRE(!delivery_is_configured(&store));
    REQUIRE(!delivery_process(&store, now, &sent, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT attempts FROM outbox") == 0);
    REQUIRE(setenv("CERTIFICATI_SMTP_URL", "smtp://user:password@127.0.0.1:1", 1) == 0);
    REQUIRE(!delivery_is_configured(&store));
    REQUIRE(setenv("CERTIFICATI_SMTP_URL", "smtp://127.0.0.1:1", 1) == 0);
    REQUIRE(delivery_is_configured(&store));
    /* A deliberately invalid subject fails before libcurl can contact any server. */
    sql(&store, "UPDATE outbox SET subject='Invalid'||char(10)||'Bcc: injected@example.test'");
    int64_t instant = now;
    for (int attempt = 1; attempt <= 5; ++attempt) {
        REQUIRE(!delivery_process(&store, instant, &sent, error, sizeof error) && sent == 0);
        REQUIRE(scalar(&store, "SELECT attempts FROM outbox") == attempt);
        REQUIRE(scalar(&store, "SELECT status='failed' AND sent_at IS NULL AND length(last_error)>0 FROM outbox"));
        REQUIRE(delivery_process(&store, instant + 1, &sent, error, sizeof error) && sent == 0);
        REQUIRE(scalar(&store, "SELECT attempts FROM outbox") == attempt);
        instant += INT64_C(60) << (attempt - 1);
    }
    REQUIRE(delivery_process(&store, instant + 10000, &sent, error, sizeof error) && sent == 0);
    REQUIRE(scalar(&store, "SELECT attempts FROM outbox") == 5);
    no_configuration();
    sql(&store, "UPDATE outbox SET status='sending',attempts=1,next_attempt=2100000120");
    REQUIRE(delivery_process(&store, now + 1, &sent, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT status='sending' FROM outbox"));
    REQUIRE(delivery_process(&store, now + 120, &sent, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT status='failed' AND attempts=1 FROM outbox"));
    sql(&store, "UPDATE certificates SET archived=1");
    REQUIRE(delivery_process(&store, now + 121, &sent, error, sizeof error));
    REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 0);
    store_close(&store);
}

static void test_stale_technical_attachments(void)
{
    for (int scenario = 0; scenario < 3; ++scenario) {
        Store store;
        setup(&store);
        sql(&store, "INSERT INTO contacts VALUES(1,'technical','Tecnico','tech@example.test')");
        int queued = 0, sent = -1;
        REQUIRE(delivery_queue_certificate(&store, 1, pem, now, &queued, error, sizeof error) && queued == 1);
        if (scenario == 0) {
            sql(&store, "UPDATE outbox SET status='sending',attempts=1,next_attempt=2100000120;"
                "UPDATE certificates SET archived=1");
        } else if (scenario == 1) {
            sql(&store, "UPDATE certificates SET not_after=2100000000");
        } else {
            sql(&store, "UPDATE certificates SET not_before=2100001000");
        }
        REQUIRE(delivery_process(&store, now + 120, &sent, error, sizeof error) && sent == 0);
        REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 0);
        store_close(&store);
    }
}

static void test_saved_profile_sender_and_disabled_delivery(void)
{
    Store store;
    setup(&store);
    sql(&store, "INSERT INTO contacts VALUES(1,'business','Business','business@example.test')");
    REQUIRE(delivery_queue_expiry(&store, 1, 30, now, error, sizeof error));
    SmtpSettings draft = {
        .enabled = 0, .host = "smtp.example.test", .port = 587,
        .security = "starttls", .from_email = "ui-sender@example.test",
        .username = "", .password = ""
    }, resolved = {0};
    REQUIRE(smtp_settings_prepare(&store, &draft, 0, &resolved, error, sizeof error));
    REQUIRE(smtp_settings_save(&store, &resolved, now, error, sizeof error));
    REQUIRE(setenv("CERTIFICATI_SMTP_URL", "smtp://127.0.0.1:1", 1) == 0);
    REQUIRE(setenv("CERTIFICATI_SMTP_FROM", "environment-sender@example.test", 1) == 0);
    REQUIRE(!delivery_is_configured(&store));
    int sent = -1;
    REQUIRE(delivery_process(&store, now, &sent, error, sizeof error) && sent == 0);
    REQUIRE(scalar(&store, "SELECT sum(attempts) FROM outbox") == 0);
    /* A paused profile does not inspect or decrypt even an unusable secret. */
    sql(&store, "UPDATE smtp_settings SET username='smtp-test',password_cipher=x'01'");
    REQUIRE(delivery_process(&store, now, &sent, error, sizeof error) && sent == 0);
    REQUIRE(scalar(&store, "SELECT sum(attempts) FROM outbox") == 0);
    size_t length;
    char *message = delivery_message(&store, 1, &length, error, sizeof error);
    REQUIRE(message && length == strlen(message));
    REQUIRE(strstr(message, "From: <ui-sender@example.test>\r\n"));
    REQUIRE(!strstr(message, "environment-sender@example.test"));
    free(message);
    resolved.enabled = 1;
    REQUIRE(smtp_settings_save(&store, &resolved, now + 1, error, sizeof error));
    REQUIRE(delivery_is_configured(&store));
    /* A malformed subject proves the enabled worker claims the row without
       contacting the configured host. */
    sql(&store, "UPDATE outbox SET subject='Invalid'||char(10)||'Bcc: injected@example.test'");
    REQUIRE(!delivery_process(&store, now + 1, &sent, error, sizeof error) && sent == 0);
    REQUIRE(scalar(&store, "SELECT attempts FROM outbox") == 1);
    smtp_settings_free(&resolved);
    no_configuration();
    store_close(&store);
}

/* This fake server never advertises STARTTLS and must never receive an email. */
static void fake_plain_smtp(int listener)
{
    alarm(8);
    int client = accept(listener, NULL, NULL);
    if (client < 0) _exit(2);
    const char greeting[] = "220 localhost test server\r\n";
    if (write(client, greeting, sizeof greeting - 1) != (ssize_t)(sizeof greeting - 1)) _exit(3);
    char line[1024];
    size_t used = 0;
    while (used + 1 < sizeof line) {
        ssize_t got = read(client, line + used, 1);
        if (got <= 0) _exit(4);
        ++used;
        if (used >= 2 && line[used - 2] == '\r' && line[used - 1] == '\n') break;
    }
    line[used] = 0;
    if (strncmp(line, "EHLO ", 5)) _exit(5);
    const char hello[] = "250-localhost\r\n250 SIZE 1000000\r\n";
    if (write(client, hello, sizeof hello - 1) != (ssize_t)(sizeof hello - 1)) _exit(6);
    ssize_t got = read(client, line, sizeof line - 1);
    if (got > 0) {
        line[got] = 0;
        if (strstr(line, "MAIL FROM") || strstr(line, "DATA")) _exit(7);
        if (!strncmp(line, "QUIT", 4)) {
            const char goodbye[] = "221 Bye\r\n";
            if (write(client, goodbye, sizeof goodbye - 1) != (ssize_t)(sizeof goodbye - 1)) _exit(8);
        }
    }
    close(client); close(listener);
    _exit(0);
}

static void test_starttls_is_mandatory(void)
{
    Store store;
    setup(&store);
    sql(&store, "INSERT INTO contacts VALUES(1,'business','Business','business@example.test')");
    REQUIRE(delivery_queue_expiry(&store, 1, 30, now, error, sizeof error));
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(listener >= 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    REQUIRE(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    REQUIRE(bind(listener, (struct sockaddr *)&address, sizeof address) == 0);
    REQUIRE(listen(listener, 1) == 0);
    socklen_t size = sizeof address;
    REQUIRE(getsockname(listener, (struct sockaddr *)&address, &size) == 0);
    pid_t child = fork();
    REQUIRE(child >= 0);
    if (!child) fake_plain_smtp(listener);
    char url[128];
    snprintf(url, sizeof url, "smtp://127.0.0.1:%u", ntohs(address.sin_port));
    REQUIRE(setenv("CERTIFICATI_SMTP_URL", url, 1) == 0);
    REQUIRE(setenv("CERTIFICATI_SMTP_FROM", "sender@example.test", 1) == 0);
    int sent = -1;
    REQUIRE(!delivery_process(&store, now, &sent, error, sizeof error) && sent == 0);
    REQUIRE(scalar(&store, "SELECT status='failed' AND attempts=1 AND sent_at IS NULL FROM outbox"));
    int status;
    REQUIRE(waitpid(child, &status, 0) == child);
    REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(listener);
    no_configuration();
    store_close(&store);
}

static int read_smtp_line(int socket_fd, SSL *tls, char *line, size_t size)
{
    size_t used = 0;
    while (used + 1 < size) {
        int got = tls ? SSL_read(tls, line + used, 1) : (int)read(socket_fd, line + used, 1);
        if (got <= 0) return 0;
        ++used;
        if (used >= 2 && line[used - 2] == '\r' && line[used - 1] == '\n') {
            line[used] = 0;
            return 1;
        }
    }
    return 0;
}

static int write_smtp(int socket_fd, SSL *tls, const char *text)
{
    size_t length = strlen(text);
    return tls ? SSL_write(tls, text, (int)length) == (int)length :
        write(socket_fd, text, length) == (ssize_t)length;
}

/* Receives only connection setup: greeting, STARTTLS, AUTH and optional QUIT.
   The child fails if libcurl sends any envelope or message command. */
static void fake_tls_probe(int listener, SSL_CTX *context, int starttls, int reject_auth,
                            int untrusted)
{
    alarm(8);
    int client = accept(listener, NULL, NULL);
    if (client < 0) _exit(10);
    char line[2048];
    if (starttls) {
        if (!write_smtp(client, NULL, "220 localhost test server\r\n") ||
            !read_smtp_line(client, NULL, line, sizeof line) || strncmp(line, "EHLO ", 5) ||
            !write_smtp(client, NULL, "250-localhost\r\n250 STARTTLS\r\n") ||
            !read_smtp_line(client, NULL, line, sizeof line) || strcmp(line, "STARTTLS\r\n") ||
            !write_smtp(client, NULL, "220 Begin TLS\r\n")) _exit(11);
    }
    SSL *tls = SSL_new(context);
    if (!tls || !SSL_set_fd(tls, client)) _exit(12);
    int connected = SSL_accept(tls);
    if (untrusted) {
        /* Depending on TLS implementation the peer may close just after the
           handshake; in either case no SMTP command may follow. */
        if (connected == 1 && read_smtp_line(client, tls, line, sizeof line)) _exit(13);
        SSL_free(tls); close(client); close(listener); _exit(0);
    }
    if (connected != 1) _exit(14);
    if (!starttls && !write_smtp(client, tls, "220 localhost test server\r\n")) _exit(15);
    if (!read_smtp_line(client, tls, line, sizeof line) || strncmp(line, "EHLO ", 5) ||
        !write_smtp(client, tls, "250-localhost\r\n250 AUTH PLAIN\r\n") ||
        !read_smtp_line(client, tls, line, sizeof line)) _exit(16);
    if (strncmp(line, "AUTH PLAIN", 10)) _exit(17);
    char *encoded = line + 10;
    while (*encoded == ' ') ++encoded;
    if (*encoded == '\r') {
        if (!write_smtp(client, tls, "334 \r\n") ||
            !read_smtp_line(client, tls, line, sizeof line)) _exit(18);
        encoded = line;
    }
    char *ending = strstr(encoded, "\r\n");
    if (!ending) _exit(19);
    *ending = 0;
    size_t encoded_length = strlen(encoded);
    if (encoded_length > 512 || encoded_length % 4) _exit(20);
    unsigned char credentials[512];
    int decoded = EVP_DecodeBlock(credentials, (const unsigned char *)encoded, (int)encoded_length);
    while (encoded_length && encoded[encoded_length - 1] == '=') { --decoded; --encoded_length; }
    static const unsigned char expected[] = "\0smtp-test\0probe-secret";
    if (decoded != (int)sizeof expected - 1 || memcmp(credentials, expected, sizeof expected - 1)) _exit(21);
    memset(credentials, 0, sizeof credentials);
    if (!write_smtp(client, tls, reject_auth ? "535 Authentication rejected\r\n" : "235 Authentication successful\r\n")) _exit(22);
    if (read_smtp_line(client, tls, line, sizeof line)) {
        if (strcmp(line, "QUIT\r\n")) _exit(23);
        (void)write_smtp(client, tls, "221 Bye\r\n");
    }
    SSL_free(tls); close(client); close(listener); _exit(0);
}

static void test_connection_probe_tls_and_auth_without_email(void)
{
    EVP_PKEY_CTX *key_context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;
    REQUIRE(key_context && EVP_PKEY_keygen_init(key_context) > 0);
    REQUIRE(EVP_PKEY_CTX_set_rsa_keygen_bits(key_context, 2048) > 0);
    REQUIRE(EVP_PKEY_keygen(key_context, &key) > 0);
    EVP_PKEY_CTX_free(key_context);
    X509 *certificate = X509_new();
    REQUIRE(certificate && X509_set_version(certificate, 2));
    REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(certificate), 42));
    REQUIRE(X509_gmtime_adj(X509_getm_notBefore(certificate), -60));
    REQUIRE(X509_gmtime_adj(X509_getm_notAfter(certificate), 86400));
    REQUIRE(X509_set_pubkey(certificate, key));
    X509_NAME *name = X509_NAME_new();
    REQUIRE(name && X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char *)"127.0.0.1", -1, -1, 0));
    REQUIRE(X509_set_subject_name(certificate, name));
    REQUIRE(X509_set_issuer_name(certificate, name));
    X509_NAME_free(name);
    X509_EXTENSION *san = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, "IP:127.0.0.1");
    REQUIRE(san && X509_add_ext(certificate, san, -1));
    X509_EXTENSION_free(san);
    REQUIRE(X509_sign(certificate, key, EVP_sha256()) > 0);
    SSL_CTX *tls_context = SSL_CTX_new(TLS_server_method());
    REQUIRE(tls_context && SSL_CTX_set_min_proto_version(tls_context, TLS1_2_VERSION));
    REQUIRE(SSL_CTX_use_certificate(tls_context, certificate));
    REQUIRE(SSL_CTX_use_PrivateKey(tls_context, key));
    char ca_path[] = "/tmp/certificati-smtp-ca-XXXXXX";
    int ca_fd = mkstemp(ca_path);
    REQUIRE(ca_fd >= 0);
    FILE *ca_file = fdopen(ca_fd, "w");
    REQUIRE(ca_file && PEM_write_X509(ca_file, certificate));
    REQUIRE(fclose(ca_file) == 0);
    X509_free(certificate); EVP_PKEY_free(key);
    for (int scenario = 0; scenario < 4; ++scenario) {
        int listener = socket(AF_INET, SOCK_STREAM, 0);
        REQUIRE(listener >= 0);
        struct sockaddr_in address;
        memset(&address, 0, sizeof address);
        address.sin_family = AF_INET;
        REQUIRE(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
        REQUIRE(bind(listener, (struct sockaddr *)&address, sizeof address) == 0);
        REQUIRE(listen(listener, 1) == 0);
        socklen_t size = sizeof address;
        REQUIRE(getsockname(listener, (struct sockaddr *)&address, &size) == 0);
        int starttls = scenario == 1;
        int reject_auth = scenario == 2, untrusted = scenario == 3;
        pid_t child = fork();
        REQUIRE(child >= 0);
        if (!child) fake_tls_probe(listener, tls_context, starttls, reject_auth, untrusted);
        if (untrusted) REQUIRE(unsetenv("CERTIFICATI_SMTP_CA_FILE") == 0);
        else REQUIRE(setenv("CERTIFICATI_SMTP_CA_FILE", ca_path, 1) == 0);
        SmtpSettings draft = {
            .enabled = 1, .port = ntohs(address.sin_port), .password_set = 1,
            .host = "127.0.0.1", .security = starttls ? "starttls" : "tls",
            .from_email = "sender@example.test", .username = "smtp-test", .password = "probe-secret"
        };
        int connected;
        if (scenario == 0) {
            Store store;
            REQUIRE(store_open(&store, ":memory:", error, sizeof error));
            SmtpSettings resolved = {0}, public_settings = {0}, retained = {0};
            REQUIRE(smtp_settings_prepare(&store, &draft, 0, &resolved, error, sizeof error));
            REQUIRE(smtp_settings_save(&store, &resolved, now, error, sizeof error));
            smtp_settings_free(&resolved);
            REQUIRE(smtp_settings_load(&store, 0, &public_settings, error, sizeof error));
            REQUIRE(public_settings.password_set && !public_settings.password);
            REQUIRE(delivery_is_configured(&store));
            public_settings.password = strdup("");
            REQUIRE(public_settings.password);
            REQUIRE(smtp_settings_prepare(&store, &public_settings, 0, &retained, error, sizeof error));
            smtp_settings_free(&public_settings);
            connected = delivery_test_connection(&retained, error, sizeof error);
            smtp_settings_free(&retained);
            REQUIRE(scalar(&store, "SELECT count(*) FROM outbox") == 0);
            store_close(&store);
        } else connected = delivery_test_connection(&draft, error, sizeof error);
        REQUIRE(connected == (!reject_auth && !untrusted));
        REQUIRE(!strstr(error, "probe-secret"));
        int status;
        REQUIRE(waitpid(child, &status, 0) == child);
        REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        close(listener);
    }
    REQUIRE(unsetenv("CERTIFICATI_SMTP_CA_FILE") == 0);
    REQUIRE(unlink(ca_path) == 0);
    SSL_CTX_free(tls_context);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    generate_public_certificate();
    test_expiry_queue_and_obsolete_thresholds();
    test_custom_reminders_and_escalation();
    test_monitor_event_queue_recipients_and_recovery();
    test_notification_claims_recheck_configuration();
    test_attachment_preview_and_privacy();
    test_header_injection_and_transaction_rollback();
    test_configuration_retries_and_leases();
    test_stale_technical_attachments();
    test_saved_profile_sender_and_disabled_delivery();
    test_starttls_is_mandatory();
    test_connection_probe_tls_and_auth_without_email();
    free(pem);
    puts("Test coda email, MIME e SMTP locale: OK (nessuna email esterna inviata)");
    return EXIT_SUCCESS;
}
