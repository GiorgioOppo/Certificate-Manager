#define _POSIX_C_SOURCE 200809L
#include "delivery.h"
#include "mail_templates.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <curl/curl.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define MAX_ATTEMPTS 5
#define CLAIM_LEASE 120
#define MAX_BATCH 3
#define MAX_ATTACHMENT (16U * 1024U * 1024U)

/* Recheck recipients/configuration when claiming, not only when preparing a
 * message. A disabled alert or removed contact must never cause a later send. */
#define BASE_DELIVERY_ELIGIBLE_SQL(clock_parameter) \
    "EXISTS(SELECT 1 FROM certificates certificate WHERE certificate.id=outbox.certificate_id " \
    "AND certificate.archived=0 AND (" \
    "(outbox.kind='expiry' AND NOT EXISTS(SELECT 1 FROM reminder_policies policy " \
    "WHERE policy.certificate_id=certificate.id AND policy.enabled=0) " \
    "AND EXISTS(SELECT 1 FROM contacts contact WHERE contact.certificate_id=certificate.id " \
    "AND contact.role='business' AND contact.email=outbox.recipient_email COLLATE NOCASE)) OR " \
    "(outbox.kind='certificate' AND certificate.not_before<=" clock_parameter \
    " AND certificate.not_after>" clock_parameter \
    " AND EXISTS(SELECT 1 FROM contacts contact WHERE contact.certificate_id=certificate.id " \
    "AND contact.role='technical' AND contact.email=outbox.recipient_email COLLATE NOCASE)) OR " \
    "(outbox.kind='escalation' AND EXISTS(SELECT 1 FROM reminder_policies policy " \
    "WHERE policy.certificate_id=certificate.id AND policy.enabled=1 " \
    "AND policy.escalation_email=outbox.recipient_email COLLATE NOCASE " \
    "AND EXISTS(SELECT 1 FROM notifications notification WHERE notification.certificate_id=certificate.id " \
    "AND notification.sent_at<=" clock_parameter "-policy.escalation_after_days*86400))) OR " \
    "(outbox.kind='monitor' AND EXISTS(SELECT 1 FROM monitor_events event JOIN monitors monitor " \
    "ON monitor.id=event.monitor_id JOIN monitor_recipients recipient ON recipient.monitor_id=monitor.id " \
    "WHERE event.id=outbox.event_id AND monitor.email_alerts=1 " \
    "AND recipient.email=outbox.recipient_email COLLATE NOCASE))))"

/* Opt-in copies keep the alert's original policy/validity requirements while
 * checking the current destination membership again at claim time. */
#define COPY_DELIVERY_ELIGIBLE_SQL(clock_parameter) \
    "EXISTS(SELECT 1 FROM certificates certificate WHERE certificate.id=outbox.certificate_id " \
    "AND certificate.archived=0 AND EXISTS(SELECT 1 FROM mail_templates template " \
    "WHERE template.alert=outbox.template_alert AND template.audience=outbox.template_audience " \
    "AND template.copy_enabled=1) AND ((outbox.template_audience='self' " \
    "AND EXISTS(SELECT 1 FROM mail_template_settings settings WHERE settings.id=1 " \
    "AND settings.self_email<>'' AND settings.self_email=outbox.recipient_email COLLATE NOCASE)) " \
    "OR (outbox.template_audience IN('business','technical') AND EXISTS(SELECT 1 FROM contacts contact " \
    "WHERE contact.certificate_id=certificate.id AND contact.role=outbox.template_audience " \
    "AND contact.email=outbox.recipient_email COLLATE NOCASE))) AND (" \
    "(outbox.kind='expiry' AND NOT EXISTS(SELECT 1 FROM reminder_policies policy " \
    "WHERE policy.certificate_id=certificate.id AND policy.enabled=0)) OR " \
    "(outbox.kind='certificate' AND certificate.not_before<=" clock_parameter " AND certificate.not_after>" clock_parameter \
    ") OR (outbox.kind='escalation' AND EXISTS(SELECT 1 FROM reminder_policies policy " \
    "WHERE policy.certificate_id=certificate.id AND policy.enabled=1 AND policy.escalation_email<>'' " \
    "AND EXISTS(SELECT 1 FROM notifications notification WHERE notification.certificate_id=certificate.id " \
    "AND notification.sent_at<=" clock_parameter "-policy.escalation_after_days*86400))) OR " \
    "(outbox.kind='monitor' AND EXISTS(SELECT 1 FROM monitor_events event JOIN monitors monitor " \
    "ON monitor.id=event.monitor_id WHERE event.id=outbox.event_id AND monitor.certificate_id=certificate.id " \
    "AND monitor.email_alerts=1 AND monitor.enabled=1))))"
#define DELIVERY_ELIGIBLE_SQL(clock_parameter) \
    "((outbox.template_copy=0 AND " BASE_DELIVERY_ELIGIBLE_SQL(clock_parameter) ") OR " \
    "(outbox.template_copy=1 AND " COPY_DELIVERY_ELIGIBLE_SQL(clock_parameter) "))"

/* A temporary maintenance pause must not make cleanup_queue delete the mail.
 * Recheck in both claim SELECT and CAS after a fresh post-maintenance probe. */
#define MONITOR_DELIVERY_READY_SQL(clock_parameter) \
    "(outbox.kind<>'monitor' OR NOT EXISTS(SELECT 1 FROM monitor_events event " \
    "JOIN monitor_options options ON options.monitor_id=event.monitor_id " \
    "WHERE event.id=outbox.event_id AND ((options.maintenance_start<=" clock_parameter \
    " AND options.maintenance_end>" clock_parameter \
    ") OR options.post_maintenance_check=1)))"

typedef struct { char *name, *email; char audience[16]; int copy; } Recipient;

static int error_message(char *err, size_t n, const char *format, ...)
{
    if (err != NULL && n != 0) {
        va_list args;
        va_start(args, format);
        (void)vsnprintf(err, n, format, args);
        va_end(args);
    }
    return 0;
}

static int db_error(Store *store, char *err, size_t n)
{
    return error_message(err, n, "Errore archivio email: %s", sqlite3_errmsg(store->db));
}

static int valid_store(Store *store, char *err, size_t n)
{
    return store != NULL && store->db != NULL ? 1 :
           error_message(err, n, "Archivio email non aperto.");
}

static int valid_header(const char *text)
{
    if (text == NULL) return 0;
    const unsigned char *p = (const unsigned char *)text;
    while (*p) {
        unsigned char first = *p++;
        if (first < 32 || first == 127) return 0;
        if (first < 128) continue;
        int continuation;
        unsigned int scalar;
        if (first >= 0xc2 && first <= 0xdf) { continuation = 1; scalar = first & 0x1f; }
        else if (first >= 0xe0 && first <= 0xef) { continuation = 2; scalar = first & 0x0f; }
        else if (first >= 0xf0 && first <= 0xf4) { continuation = 3; scalar = first & 0x07; }
        else return 0;
        for (int i = 0; i < continuation; ++i) {
            if ((*p & 0xc0) != 0x80) return 0;
            scalar = (scalar << 6) | (*p++ & 0x3f);
        }
        if ((continuation == 2 && scalar < 0x800) ||
            (continuation == 3 && scalar < 0x10000) || scalar > 0x10ffff ||
            (scalar >= 0xd800 && scalar <= 0xdfff)) return 0;
    }
    return 1;
}

/* A single ASCII mailbox, never a display name or a list of recipients. */
static int valid_email(const char *email)
{
    if (email == NULL || strlen(email) > 254) return 0;
    const char *at = strchr(email, '@');
    if (at == NULL || at == email || at - email > 64 || strchr(at + 1, '@') ||
        email[0] == '.' || at[-1] == '.' || !at[1]) return 0;
    for (const char *p = email; p < at; ++p) {
        unsigned char c = (unsigned char)*p;
        if (!(c < 128 && (isalnum(c) || strchr(".!#$%&'*+-/=?^_`{|}~", c)))) return 0;
        if (c == '.' && p + 1 < at && p[1] == '.') return 0;
    }
    const char *label = at + 1;
    for (const char *p = label;; ++p) {
        unsigned char c = (unsigned char)*p;
        if (!c || c == '.') {
            if (p == label || p - label > 63 || label[0] == '-' || p[-1] == '-') return 0;
            if (!c) break;
            label = p + 1;
        } else if (!(c < 128 && (isalnum(c) || c == '-'))) return 0;
    }
    return 1;
}

int delivery_is_configured(Store *store)
{
    SmtpSettings settings = {0};
    if (!smtp_settings_load(store, 0, &settings, NULL, 0)) return 0;
    int configured = settings.enabled && smtp_settings_validate(&settings, 1, NULL, 0);
    smtp_settings_free(&settings);
    return configured;
}

static int bind_text(sqlite3_stmt *stmt, int index, const char *text)
{
    return sqlite3_bind_text(stmt, index, text ? text : "", -1, SQLITE_TRANSIENT) == SQLITE_OK;
}

static char *column_text(sqlite3_stmt *stmt, int index)
{
    const unsigned char *text = sqlite3_column_text(stmt, index);
    int length = sqlite3_column_bytes(stmt, index);
    if (!text || memchr(text, 0, (size_t)length)) return NULL;
    return strdup((const char *)text);
}

static void recipients_free(Recipient *recipients, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        free(recipients[i].name);
        free(recipients[i].email);
    }
    free(recipients);
}

static int recipients_load(Store *store, int64_t cert_id, const char *role,
                           Recipient **recipients, size_t *count, char *err, size_t n)
{
    sqlite3_stmt *stmt = NULL;
    *recipients = NULL; *count = 0;
    if (sqlite3_prepare_v2(store->db,
        "SELECT name,email FROM contacts WHERE certificate_id=? AND role=? ORDER BY email",
        -1, &stmt, NULL) != SQLITE_OK) return db_error(store, err, n);
    if (sqlite3_bind_int64(stmt, 1, cert_id) != SQLITE_OK || !bind_text(stmt, 2, role)) goto fail_db;
    int result;
    while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
        char *name = column_text(stmt, 0), *email = column_text(stmt, 1);
        if (!name || !email || strlen(name) > 512 || !valid_header(name) || !valid_email(email)) {
            free(name); free(email);
            error_message(err, n, "Nome o indirizzo del referente non valido.");
            goto fail;
        }
        Recipient *next = realloc(*recipients, (*count + 1) * sizeof **recipients);
        if (!next) {
            free(name); free(email);
            error_message(err, n, "Memoria insufficiente per i referenti.");
            goto fail;
        }
        *recipients = next;
        next[*count].name = name; next[*count].email = email;
        snprintf(next[*count].audience, sizeof next[*count].audience, "%s", role);
        next[*count].copy = 0;
        ++*count;
    }
    if (result != SQLITE_DONE) goto fail_db;
    if (sqlite3_finalize(stmt) != SQLITE_OK) {
        stmt = NULL;
        goto fail_db;
    }
    return 1;
fail_db:
    db_error(store, err, n);
fail:
    sqlite3_finalize(stmt);
    recipients_free(*recipients, *count);
    *recipients = NULL; *count = 0;
    return 0;
}

static int certificate_metadata(Store *store, int64_t id, char **name,
                                int64_t *expiry, char *err, size_t n)
{
    sqlite3_stmt *stmt = NULL;
    *name = NULL;
    if (sqlite3_prepare_v2(store->db,
        "SELECT common_name,not_after FROM certificates WHERE id=? AND archived=0",
        -1, &stmt, NULL) != SQLITE_OK) return db_error(store, err, n);
    if (sqlite3_bind_int64(stmt, 1, id) != SQLITE_OK) goto fail_db;
    int result = sqlite3_step(stmt);
    if (result != SQLITE_ROW) {
        if (result == SQLITE_DONE) error_message(err, n, "Certificato non trovato o archiviato.");
        else db_error(store, err, n);
        sqlite3_finalize(stmt);
        return 0;
    }
    *name = column_text(stmt, 0);
    *expiry = sqlite3_column_int64(stmt, 1);
    if (!*name || !valid_header(*name)) {
        free(*name); *name = NULL;
        error_message(err, n, "Nome del certificato non valido per un messaggio email.");
        sqlite3_finalize(stmt);
        return 0;
    }
    if (!(*name)[0]) {
        free(*name); *name = strdup("certificato senza nome comune");
        if (!*name) {
            error_message(err, n, "Memoria insufficiente.");
            sqlite3_finalize(stmt);
            return 0;
        }
    }
    if (sqlite3_finalize(stmt) != SQLITE_OK) { free(*name); *name = NULL; return db_error(store, err, n); }
    return 1;
fail_db:
    db_error(store, err, n);
    sqlite3_finalize(stmt);
    return 0;
}

static int utc_text(int64_t epoch, char *buffer, size_t size, int header)
{
    time_t value = (time_t)epoch;
    struct tm tm;
    if ((int64_t)value != epoch || !gmtime_r(&value, &tm)) return 0;
    if (header) {
        static const char *const days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
        static const char *const months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
        int count = snprintf(buffer, size, "%s, %02d %s %04d %02d:%02d:%02d +0000",
            days[tm.tm_wday], tm.tm_mday, months[tm.tm_mon], tm.tm_year + 1900,
            tm.tm_hour, tm.tm_min, tm.tm_sec);
        return count > 0 && (size_t)count < size;
    }
    return strftime(buffer, size, "%d/%m/%Y alle %H:%M UTC", &tm) > 0;
}

int reminder_policy_due(Store *store, int64_t cert_id, int64_t not_after,
                         int64_t now, int *threshold, char *err, size_t n)
{
    if (threshold) *threshold = -1;
    if (!valid_store(store, err, n)) return 0;
    if (!threshold || cert_id <= 0 || now < 0 || not_after < 0)
        return error_message(err, n, "Dati del promemoria non validi.");
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(store->db,
        "SELECT thresholds,enabled FROM reminder_policies WHERE certificate_id=?", -1,
        &stmt, NULL) != SQLITE_OK || sqlite3_bind_int64(stmt, 1, cert_id) != SQLITE_OK) {
        sqlite3_finalize(stmt); return db_error(store, err, n);
    }
    int result = sqlite3_step(stmt);
    char *csv = NULL;
    if (result == SQLITE_ROW) {
        if (!sqlite3_column_int(stmt, 1)) {
            sqlite3_finalize(stmt); return 1;
        }
        csv = column_text(stmt, 0);
    } else if (result == SQLITE_DONE) csv = strdup("45,30,15,2,0");
    else { sqlite3_finalize(stmt); return db_error(store, err, n); }
    if (sqlite3_finalize(stmt) != SQLITE_OK) { free(csv); return db_error(store, err, n); }
    if (!csv) return error_message(err, n, "Memoria insufficiente per le soglie.");
    unsigned char seen[3651] = {0};
    const char *cursor = csv;
    int due = -1, valid = 1;
    while (*cursor) {
        while (isspace((unsigned char)*cursor)) ++cursor;
        if (!isdigit((unsigned char)*cursor)) { valid = 0; break; }
        errno = 0;
        char *end = NULL;
        long value = strtol(cursor, &end, 10);
        if (errno || value < 0 || value > 3650 || seen[value]) { valid = 0; break; }
        seen[value] = 1;
        int64_t seconds = (int64_t)value * INT64_C(86400);
        if ((now > INT64_MAX - seconds || not_after <= now + seconds) &&
            (due < 0 || value < due)) due = (int)value;
        cursor = end;
        while (isspace((unsigned char)*cursor)) ++cursor;
        if (!*cursor) break;
        if (*cursor++ != ',' || !*cursor) { valid = 0; break; }
    }
    free(csv);
    if (!valid || !seen[0])
        return error_message(err, n, "Soglie non valide: usa giorni univoci da 0 a 3650 e includi 0.");
    *threshold = due;
    return 1;
}

/* Base recipients are loaded first. Optional copies are deduplicated by
 * mailbox, so base routing always determines the template for shared roles.
 * Among copies the personal profile takes precedence, then business/technical. */
static int append_copies(Store *store, int64_t cert_id, const char *alert,
                         Recipient **recipients, size_t *count, char *err, size_t n)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT audience,name,email FROM (SELECT template.audience AS audience,contact.name AS name,contact.email AS email FROM mail_templates template "
        "JOIN contacts contact ON contact.role=template.audience AND contact.certificate_id=?1 "
        "WHERE template.alert=?2 AND template.copy_enabled=1 AND template.audience IN('business','technical') "
        "UNION ALL SELECT 'self',settings.self_name,settings.self_email FROM mail_template_settings settings "
        "JOIN mail_templates template ON template.alert=?2 AND template.audience='self' AND template.copy_enabled=1 "
        "WHERE settings.id=1 AND settings.self_email<>'') ORDER BY CASE audience WHEN 'self' THEN 0 WHEN 'business' THEN 1 ELSE 2 END,email";
    if (sqlite3_prepare_v2(store->db, sql, -1, &stmt, NULL) != SQLITE_OK) return db_error(store, err, n);
    sqlite3_bind_int64(stmt, 1, cert_id); bind_text(stmt, 2, alert);
    int result;
    while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *audience = (const char *)sqlite3_column_text(stmt, 0);
        const char *name = (const char *)sqlite3_column_text(stmt, 1);
        const char *email = (const char *)sqlite3_column_text(stmt, 2);
        int duplicate = 0;
        for (size_t i = 0; i < *count; ++i) if (!strcasecmp((*recipients)[i].email, email)) { duplicate = 1; break; }
        if (duplicate) continue;
        if (!valid_email(email) || !valid_header(name) || strlen(name) > 512) {
            sqlite3_finalize(stmt); return error_message(err, n, "Destinatario della copia non valido.");
        }
        Recipient *next = realloc(*recipients, (*count + 1) * sizeof **recipients);
        if (!next) { sqlite3_finalize(stmt); return error_message(err, n, "Memoria insufficiente."); }
        *recipients = next;
        Recipient *recipient = &next[*count];
        memset(recipient, 0, sizeof *recipient);
        recipient->name = strdup(name); recipient->email = strdup(email);
        if (!recipient->name || !recipient->email) {
            free(recipient->name); free(recipient->email); sqlite3_finalize(stmt);
            return error_message(err, n, "Memoria insufficiente.");
        }
        snprintf(recipient->audience, sizeof recipient->audience, "%s", audience);
        recipient->copy = 1; ++*count;
    }
    sqlite3_finalize(stmt);
    return result == SQLITE_DONE ? 1 : db_error(store, err, n);
}

static int queue_rows(Store *store, int64_t cert_id, const char *kind,
                      int threshold, Recipient *recipients, size_t count,
                      const char *alert, const char *attachment, int64_t event_id,
                      int64_t now, int *queued, char *err, size_t n)
{
    sqlite3_stmt *insert = NULL, *prune = NULL, *skip = NULL;
    int outer = sqlite3_get_autocommit(store->db), added = 0;
    *queued = 0;
    if (!store_exec(store, "SAVEPOINT mail_template_queue", err, n)) return 0;
    const char *sql = "INSERT INTO outbox(certificate_id,kind,recipient_name,recipient_email,"
        "threshold,subject,body,attachment_pem,status,attempts,last_error,created_at,next_attempt,"
        "event_id,template_alert,template_audience,template_copy) "
        "SELECT ?1,?2,?3,?4,?5,?6,?7,?8,'pending',0,'',?9,0,nullif(?10,0),?11,?12,?13 "
        "WHERE (?2<>'expiry' OR NOT EXISTS(SELECT 1 FROM outbox older WHERE "
        "older.certificate_id=?1 AND older.kind='expiry' AND older.recipient_email=?4 COLLATE NOCASE AND older.threshold<?5)) "
        "AND NOT EXISTS(SELECT 1 FROM outbox prior WHERE prior.certificate_id=?1 AND prior.kind=?2 "
        "AND prior.recipient_email=?4 COLLATE NOCASE AND ((?2='monitor' AND prior.event_id=?10) OR (?2<>'monitor' AND prior.threshold=?5))) "
        "ON CONFLICT DO NOTHING";
    if (sqlite3_prepare_v2(store->db, sql, -1, &insert, NULL) != SQLITE_OK) goto fail;
    /* Decide whether this mailbox already has this exact notification, or
     * a more urgent reminder, before loading or expanding the current template.
     * Existing snapshots must remain usable after later template edits. */
    if (sqlite3_prepare_v2(store->db,
        "SELECT (?2='expiry' AND EXISTS(SELECT 1 FROM outbox older WHERE "
        "older.certificate_id=?1 AND older.kind='expiry' AND older.recipient_email=?3 COLLATE NOCASE AND older.threshold<?4)) "
        "OR EXISTS(SELECT 1 FROM outbox prior WHERE prior.certificate_id=?1 AND prior.kind=?2 "
        "AND prior.recipient_email=?3 COLLATE NOCASE AND ((?2='monitor' AND prior.event_id=?5) OR (?2<>'monitor' AND prior.threshold=?4)))",
        -1, &skip, NULL) != SQLITE_OK) goto fail;
    if (!strcmp(kind, "expiry") && sqlite3_prepare_v2(store->db,
        "DELETE FROM outbox WHERE certificate_id=? AND kind='expiry' AND recipient_email=? COLLATE NOCASE "
        "AND threshold>? AND status IN('pending','failed')", -1, &prune, NULL) != SQLITE_OK) goto fail;
    for (size_t i = 0; i < count; ++i) {
        sqlite3_reset(skip); sqlite3_clear_bindings(skip);
        if (sqlite3_bind_int64(skip, 1, cert_id) != SQLITE_OK ||
            !bind_text(skip, 2, kind) || !bind_text(skip, 3, recipients[i].email) ||
            sqlite3_bind_int(skip, 4, threshold) != SQLITE_OK ||
            sqlite3_bind_int64(skip, 5, event_id) != SQLITE_OK || sqlite3_step(skip) != SQLITE_ROW) goto fail;
        int existing = sqlite3_column_int(skip, 0);
        sqlite3_reset(skip);
        if (existing) continue;
        char *subject = NULL, *body = NULL;
        if (!mail_templates_render(store, alert, recipients[i].audience, cert_id, event_id,
            threshold, now, recipients[i].name, recipients[i].email, NULL, NULL,
            &subject, &body, err, n)) {
            char detail[512];
            snprintf(detail, sizeof detail, "%s", err && n && *err ? err : "Generazione email non riuscita.");
            error_message(err, n, "Template %s/%s, certificato #%" PRId64 ": %s",
                alert, recipients[i].audience, cert_id, detail);
            goto rollback;
        }
        int ok = 1;
        if (prune) {
            sqlite3_reset(prune); sqlite3_clear_bindings(prune);
            ok = sqlite3_bind_int64(prune, 1, cert_id) == SQLITE_OK &&
                bind_text(prune, 2, recipients[i].email) &&
                sqlite3_bind_int(prune, 3, threshold) == SQLITE_OK &&
                sqlite3_step(prune) == SQLITE_DONE;
        }
        sqlite3_reset(insert); sqlite3_clear_bindings(insert);
        ok = ok && sqlite3_bind_int64(insert, 1, cert_id) == SQLITE_OK &&
            bind_text(insert, 2, kind) && bind_text(insert, 3, recipients[i].name) &&
            bind_text(insert, 4, recipients[i].email) &&
            sqlite3_bind_int(insert, 5, threshold) == SQLITE_OK &&
            bind_text(insert, 6, subject) && bind_text(insert, 7, body) &&
            bind_text(insert, 8, attachment) && sqlite3_bind_int64(insert, 9, now) == SQLITE_OK &&
            sqlite3_bind_int64(insert, 10, event_id) == SQLITE_OK && bind_text(insert, 11, alert) &&
            bind_text(insert, 12, recipients[i].audience) && sqlite3_bind_int(insert, 13, recipients[i].copy) == SQLITE_OK &&
            sqlite3_step(insert) == SQLITE_DONE;
        free(subject); free(body);
        if (!ok) goto fail;
        added += sqlite3_changes(store->db);
    }
    sqlite3_finalize(insert); sqlite3_finalize(prune); sqlite3_finalize(skip); insert = NULL; prune = NULL; skip = NULL;
    if (!store_exec(store, "RELEASE mail_template_queue", err, n)) goto rollback;
    *queued = added; return 1;
fail:
    db_error(store, err, n);
rollback:
    sqlite3_finalize(insert); sqlite3_finalize(prune); sqlite3_finalize(skip);
    sqlite3_exec(store->db, outer ? "ROLLBACK" : "ROLLBACK TO mail_template_queue; RELEASE mail_template_queue", NULL, NULL, NULL);
    return 0;
}

int delivery_queue_expiry(Store *store, int64_t cert_id, int threshold,
                          int64_t now, char *err, size_t n)
{
    if (!valid_store(store, err, n)) return 0;
    if (threshold < 0 || threshold > 3650)
        return error_message(err, n, "Soglia del promemoria email non valida.");
    Recipient *recipients = NULL; size_t count = 0; int queued = 0;
    const char *alert = mail_templates_expiry_alert(threshold);
    int ok = recipients_load(store, cert_id, "business", &recipients, &count, err, n) &&
        append_copies(store, cert_id, alert, &recipients, &count, err, n) &&
        queue_rows(store, cert_id, "expiry", threshold, recipients, count, alert, "", 0, now, &queued, err, n);
    recipients_free(recipients, count); return ok;
}

int reminder_policy_check_escalation(Store *store, int64_t cert_id,
                                     int64_t now, int *queued, char *err, size_t n)
{
    if (queued) *queued = 0;
    if (!valid_store(store, err, n)) return 0;
    if (cert_id <= 0 || now < 0)
        return error_message(err, n, "Dati dell'escalation non validi.");
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(store->db,
        "SELECT policy.escalation_name,policy.escalation_email FROM reminder_policies policy "
        "JOIN certificates certificate ON certificate.id=policy.certificate_id "
        "WHERE policy.certificate_id=?1 AND certificate.archived=0 AND policy.enabled=1 "
        "AND policy.escalation_email<>'' AND EXISTS(SELECT 1 FROM notifications notification "
        "WHERE notification.certificate_id=certificate.id "
        "AND notification.sent_at<=?2-policy.escalation_after_days*86400)",
        -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int64(stmt, 1, cert_id) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 2, now) != SQLITE_OK) {
        sqlite3_finalize(stmt); return db_error(store, err, n);
    }
    int result = sqlite3_step(stmt);
    if (result == SQLITE_DONE) { sqlite3_finalize(stmt); return 1; }
    if (result != SQLITE_ROW) { sqlite3_finalize(stmt); return db_error(store, err, n); }
    Recipient recipient = {.name=column_text(stmt, 0), .email=column_text(stmt, 1)};
    int finalized = sqlite3_finalize(stmt);
    if (finalized != SQLITE_OK || !recipient.name || !recipient.email ||
        strlen(recipient.name) > 512 || !valid_header(recipient.name) || !valid_email(recipient.email)) {
        free(recipient.name); free(recipient.email);
        return error_message(err, n, "Destinatario dell'escalation non valido.");
    }
    Recipient *recipients = malloc(sizeof *recipients);
    if (!recipients) { free(recipient.name); free(recipient.email); return error_message(err, n, "Memoria insufficiente."); }
    *recipients = recipient; size_t count = 1;
    char *audience = mail_templates_audience(store, cert_id, recipient.email, err, n);
    int added = 0, ok = audience != NULL;
    if (audience) { snprintf(recipients[0].audience, sizeof recipients[0].audience, "%s", audience); free(audience); }
    if (ok) ok = append_copies(store, cert_id, "escalation", &recipients, &count, err, n) &&
        queue_rows(store, cert_id, "escalation", -1, recipients, count, "escalation", "", 0, now, &added, err, n);
    if (ok && queued) *queued = added;
    recipients_free(recipients, count); return ok;
}

int delivery_queue_monitor_event(Store *store, int64_t event_id, int64_t now,
                                  int *queued, char *err, size_t n)
{
    if (queued) *queued = 0;
    if (!valid_store(store, err, n)) return 0;
    if (event_id <= 0 || now < 0)
        return error_message(err, n, "Evento del monitor non valido.");
    sqlite3_stmt *stmt = NULL;
    char *target = NULL, *kind = NULL, *detail = NULL, *expected = NULL, *observed = NULL;
    Recipient *recipients = NULL;
    size_t count = 0;
    int64_t cert_id = 0, monitor_id = 0;
    int ok = 0, added = 0;
    if (sqlite3_prepare_v2(store->db,
        "SELECT monitor.id,monitor.certificate_id,monitor.target,event.kind,event.message,"
        "event.expected_fingerprint,event.observed_fingerprint FROM monitor_events event "
        "JOIN monitors monitor ON monitor.id=event.monitor_id WHERE event.id=? AND monitor.email_alerts=1",
        -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int64(stmt, 1, event_id) != SQLITE_OK) goto fail_db;
    int result = sqlite3_step(stmt);
    if (result == SQLITE_DONE) { ok = 1; goto done; }
    if (result != SQLITE_ROW) goto fail_db;
    monitor_id = sqlite3_column_int64(stmt, 0); cert_id = sqlite3_column_int64(stmt, 1);
    target = column_text(stmt, 2); kind = column_text(stmt, 3); detail = column_text(stmt, 4);
    expected = column_text(stmt, 5); observed = column_text(stmt, 6);
    if (sqlite3_finalize(stmt) != SQLITE_OK) { stmt = NULL; goto fail_db; }
    stmt = NULL;
    if (!target || !kind || !detail || !expected || !observed || !valid_header(target)) {
        error_message(err, n, "Dati dell'evento del monitor non validi."); goto done;
    }
    if (sqlite3_prepare_v2(store->db,
        "SELECT name,email FROM monitor_recipients WHERE monitor_id=? ORDER BY email", -1,
        &stmt, NULL) != SQLITE_OK || sqlite3_bind_int64(stmt, 1, monitor_id) != SQLITE_OK) goto fail_db;
    while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
        char *name = column_text(stmt, 0), *email = column_text(stmt, 1);
        if (!name || !email || strlen(name) > 512 || !valid_header(name) || !valid_email(email)) {
            free(name); free(email); error_message(err, n, "Destinatario del monitor non valido."); goto done;
        }
        Recipient *next = realloc(recipients, (count + 1) * sizeof *recipients);
        if (!next) { free(name); free(email); error_message(err, n, "Memoria insufficiente."); goto done; }
        recipients = next; recipients[count] = (Recipient){.name=name, .email=email};
        char *audience = mail_templates_audience(store, cert_id, email, err, n);
        if (!audience) { ++count; goto done; }
        snprintf(recipients[count].audience, sizeof recipients[count].audience, "%s", audience);
        free(audience); ++count;
    }
    if (result != SQLITE_DONE) goto fail_db;
    if (sqlite3_finalize(stmt) != SQLITE_OK) { stmt = NULL; goto fail_db; }
    stmt = NULL;
    if (!append_copies(store, cert_id, kind, &recipients, &count, err, n) ||
        !queue_rows(store, cert_id, "monitor", -1, recipients, count, kind, "", event_id, now, &added, err, n)) goto done;
    if (queued) *queued = added;
    ok = 1;
    goto done;
fail_db:
    db_error(store, err, n);
done:
    sqlite3_finalize(stmt); free(target); free(kind); free(detail); free(expected); free(observed);
    recipients_free(recipients, count);
    return ok;
}

static int valid_pem_bundle(const char *pem)
{
    if (!pem) return 0;
    size_t length = strnlen(pem, MAX_ATTACHMENT + 1);
    if (!length || length > MAX_ATTACHMENT) return 0;
    const char *p = pem;
    size_t count = 0;
    static const char begin[] = "-----BEGIN CERTIFICATE-----";
    static const char end[] = "-----END CERTIFICATE-----";
    while (*p) {
        while (*p && isspace((unsigned char)*p)) ++p;
        if (!*p) break;
        if (strncmp(p, begin, sizeof begin - 1)) return 0;
        const char *finish = strstr(p + sizeof begin - 1, end);
        if (!finish) return 0;
        finish += sizeof end - 1;
        BIO *bio = BIO_new_mem_buf(p, (int)(finish - p));
        X509 *cert = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
        BIO_free(bio);
        if (!cert) return 0;
        X509_free(cert);
        p = finish;
        if (++count > 1024) return 0;
    }
    return count != 0;
}

int delivery_queue_certificate(Store *store, int64_t cert_id, const char *pem_bundle,
                               int64_t now, int *queued, char *err, size_t n)
{
    if (queued) *queued = 0;
    if (!valid_store(store, err, n)) return 0;
    if (!valid_pem_bundle(pem_bundle)) return error_message(err, n, "Allegato non valido: sono ammessi soltanto certificati PEM.");
    char *name = NULL;
    int64_t expiry;
    char date[64];
    if (!certificate_metadata(store, cert_id, &name, &expiry, err, n)) return 0;
    if (!utc_text(expiry, date, sizeof date, 0)) { free(name); return error_message(err, n, "Data di scadenza non rappresentabile."); }
    Recipient *recipients = NULL;
    size_t count = 0;
    if (!recipients_load(store, cert_id, "technical", &recipients, &count, err, n)) { free(name); return 0; }
    if (!count) { free(name); recipients_free(recipients, count); return error_message(err, n, "Aggiungi almeno un referente tecnico prima di preparare l'invio del certificato."); }
    int added = 0;
    int ok = append_copies(store, cert_id, "certificate", &recipients, &count, err, n) &&
        queue_rows(store, cert_id, "certificate", -1, recipients, count, "certificate", pem_bundle, 0, now, &added, err, n);
    if (ok && queued) *queued = added;
    free(name); recipients_free(recipients, count); return ok;
}

static void base64(FILE *out, const unsigned char *text, size_t length, int wrap)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t column = 0;
    for (size_t i = 0; i < length; i += 3) {
        unsigned int a = text[i], b = i + 1 < length ? text[i + 1] : 0;
        unsigned int c = i + 2 < length ? text[i + 2] : 0;
        fputc(alphabet[a >> 2], out);
        fputc(alphabet[((a & 3) << 4) | (b >> 4)], out);
        fputc(i + 1 < length ? alphabet[((b & 15) << 2) | (c >> 6)] : '=', out);
        fputc(i + 2 < length ? alphabet[c & 63] : '=', out);
        column += 4;
        if (wrap && column == 76) { fputs("\r\n", out); column = 0; }
    }
    if (wrap && column) fputs("\r\n", out);
}

/* Fold encoded words below the RFC 2047 limit, preserving UTF-8 boundaries. */
static void encoded_header(FILE *out, const char *text)
{
    size_t remaining = strlen(text);
    const unsigned char *p = (const unsigned char *)text;
    int first = 1;
    while (remaining) {
        size_t length = remaining > 42 ? 42 : remaining;
        if (length < remaining)
            while (length && (p[length] & 0xc0) == 0x80) --length;
        if (!length) length = remaining > 42 ? 42 : remaining;
        if (!first) fputs("\r\n ", out);
        fputs("=?UTF-8?B?", out); base64(out, p, length, 0); fputs("?=", out);
        p += length; remaining -= length; first = 0;
    }
}

static char *canonical_text(const char *text)
{
    size_t length = strlen(text);
    if (length > (SIZE_MAX - 1) / 2) return NULL;
    char *result = malloc(length * 2 + 1);
    if (!result) return NULL;
    size_t written = 0;
    for (size_t i = 0; i < length; ++i) {
        if (text[i] == '\r' || text[i] == '\n') {
            if (text[i] == '\r' && i + 1 < length && text[i + 1] == '\n') ++i;
            result[written++] = '\r'; result[written++] = '\n';
        } else result[written++] = text[i];
    }
    result[written] = 0;
    return result;
}

static char *message_from(Store *store, int64_t outbox_id, const char *sender,
                          size_t *length, char *err, size_t n)
{
    if (length) *length = 0;
    if (!valid_store(store, err, n)) return NULL;
    if (!valid_email(sender)) { error_message(err, n, "Indirizzo mittente SMTP non valido."); return NULL; }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(store->db,
        "SELECT recipient_name,recipient_email,subject,body,attachment_pem,created_at "
        "FROM outbox WHERE id=?", -1, &stmt, NULL) != SQLITE_OK) { db_error(store, err, n); return NULL; }
    if (sqlite3_bind_int64(stmt, 1, outbox_id) != SQLITE_OK) { db_error(store, err, n); sqlite3_finalize(stmt); return NULL; }
    int result = sqlite3_step(stmt);
    if (result != SQLITE_ROW) {
        if (result == SQLITE_DONE) error_message(err, n, "Messaggio email non trovato.");
        else db_error(store, err, n);
        sqlite3_finalize(stmt); return NULL;
    }
    char *name = column_text(stmt, 0), *email = column_text(stmt, 1);
    char *subject = column_text(stmt, 2), *body = column_text(stmt, 3);
    char *attachment = column_text(stmt, 4);
    int64_t created_at = sqlite3_column_int64(stmt, 5);
    int finalized = sqlite3_finalize(stmt);
    if (finalized != SQLITE_OK || !name || !email || !subject || !body || !attachment ||
        !valid_header(name) || !valid_email(email) || !valid_header(subject)) {
        error_message(err, n, "Dati del messaggio email non validi.");
        free(name); free(email); free(subject); free(body); free(attachment); return NULL;
    }
    char *canonical = canonical_text(body);
    free(body); body = canonical;
    if (!body) {
        error_message(err, n, "Memoria insufficiente per il testo email.");
        free(name); free(email); free(subject); free(attachment); return NULL;
    }
    char date[80];
    if (!utc_text(created_at, date, sizeof date, 1)) {
        error_message(err, n, "Data del messaggio non rappresentabile.");
        free(name); free(email); free(subject); free(body); free(attachment); return NULL;
    }
    char *message = NULL;
    size_t message_length = 0;
    FILE *out = open_memstream(&message, &message_length);
    if (!out) {
        error_message(err, n, "Memoria insufficiente per il messaggio email.");
        free(name); free(email); free(subject); free(body); free(attachment); return NULL;
    }
    fprintf(out, "Date: %s\r\nMessage-ID: <certificati.%" PRId64 ".%" PRId64 "@localhost.invalid>\r\n"
        "From: <%s>\r\nTo: ", date, outbox_id, created_at, sender);
    if (*name) { encoded_header(out, name); fputs("\r\n ", out); }
    fprintf(out, "<%s>\r\nSubject: ", email);
    encoded_header(out, subject);
    fputs("\r\nMIME-Version: 1.0\r\n", out);
    char boundary[100];
    snprintf(boundary, sizeof boundary, "certificati-%" PRId64 "-%" PRId64, outbox_id, created_at);
    if (*attachment) fprintf(out, "Content-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n--%s\r\n", boundary, boundary);
    fputs("Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n", out);
    base64(out, (const unsigned char *)body, strlen(body), 1);
    if (*attachment) {
        fprintf(out, "\r\n--%s\r\nContent-Type: application/x-pem-file; name=\"certificate.pem\"\r\n"
            "Content-Disposition: attachment; filename=\"certificate.pem\"\r\n"
            "Content-Transfer-Encoding: base64\r\n\r\n", boundary);
        base64(out, (const unsigned char *)attachment, strlen(attachment), 1);
        fprintf(out, "\r\n--%s--\r\n", boundary);
    }
    int ok = !ferror(out);
    if (fclose(out) != 0) ok = 0;
    free(name); free(email); free(subject); free(body); free(attachment);
    if (!ok) { free(message); error_message(err, n, "Impossibile preparare il messaggio email."); return NULL; }
    if (length) *length = message_length;
    return message;
}

char *delivery_message(Store *store, int64_t outbox_id, size_t *length,
                       char *err, size_t n)
{
    if (length) *length = 0;
    if (!valid_store(store, err, n)) return NULL;
    SmtpSettings settings = {0};
    if (!smtp_settings_load(store, 0, &settings, err, n)) return NULL;
    const char *sender = settings.from_email && settings.from_email[0] ?
        settings.from_email : "certificati@localhost.invalid";
    char *message = message_from(store, outbox_id, sender, length, err, n);
    smtp_settings_free(&settings);
    return message;
}

typedef struct { const char *message; size_t length, offset; } Upload;

static size_t upload_read(char *buffer, size_t size, size_t count, void *data)
{
    Upload *upload = data;
    if (size && count > SIZE_MAX / size) return CURL_READFUNC_ABORT;
    size_t available = size * count;
    size_t remaining = upload->length - upload->offset;
    if (available > remaining) available = remaining;
    memcpy(buffer, upload->message + upload->offset, available);
    upload->offset += available;
    return available;
}

static CURLcode smtp_options(CURL *curl, const SmtpSettings *settings,
                             const char *url, long timeout)
{
    CURLcode result = CURLE_OK;
#define OPTION(option, value) do { if (result == CURLE_OK) result = curl_easy_setopt(curl, option, value); } while (0)
    OPTION(CURLOPT_URL, url);
#if LIBCURL_VERSION_NUM >= 0x075500
    OPTION(CURLOPT_PROTOCOLS_STR, "smtp,smtps");
#else
    OPTION(CURLOPT_PROTOCOLS, (long)(CURLPROTO_SMTP | CURLPROTO_SMTPS));
#endif
    OPTION(CURLOPT_PROXY, "");
    OPTION(CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
    OPTION(CURLOPT_SSL_VERIFYPEER, 1L);
    OPTION(CURLOPT_SSL_VERIFYHOST, 2L);
    OPTION(CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_2);
    const char *ca_file = getenv("CERTIFICATI_SMTP_CA_FILE");
    if (ca_file && ca_file[0]) OPTION(CURLOPT_CAINFO, ca_file);
    OPTION(CURLOPT_CONNECTTIMEOUT, 5L);
    OPTION(CURLOPT_TIMEOUT, timeout);
    OPTION(CURLOPT_NOSIGNAL, 1L);
    if (settings->username && settings->username[0]) {
        OPTION(CURLOPT_USERNAME, settings->username);
        OPTION(CURLOPT_PASSWORD, settings->password);
    }
#undef OPTION
    return result;
}

int delivery_test_connection(const SmtpSettings *settings, char *err, size_t n)
{
    if (!smtp_settings_validate(settings, 1, err, n)) return 0;
    if (settings->username && settings->username[0] &&
        (!settings->password || !settings->password[0]))
        return error_message(err, n, "La password SMTP non è disponibile per la prova.");
    char *url = smtp_settings_url(settings, err, n);
    if (!url) return 0;
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        free(url);
        return error_message(err, n, "Impossibile inizializzare il supporto SMTP.");
    }
    CURL *curl = curl_easy_init();
    if (!curl) {
        free(url); curl_global_cleanup();
        return error_message(err, n, "Impossibile inizializzare il client SMTP.");
    }
    char diagnostics[CURL_ERROR_SIZE] = {0};
    CURLcode result = smtp_options(curl, settings, url, 10L);
    if (result == CURLE_OK) result = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, diagnostics);
    /* Bound each greeting/AUTH response explicitly as well as the complete
     * connection probe. This never extends the overall ten-second deadline. */
    if (result == CURLE_OK) result = curl_easy_setopt(curl, CURLOPT_SERVER_RESPONSE_TIMEOUT, 5L);
    /* SMTP greeting, TLS and AUTH are part of connection setup in libcurl.
       No MAIL FROM, recipients or upload is configured for this handle. */
    if (result == CURLE_OK) result = curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
    if (result == CURLE_OK) result = curl_easy_perform(curl);
    long response = 0;
    (void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
    curl_easy_cleanup(curl); curl_global_cleanup(); free(url);
    if (result != CURLE_OK) {
        /* Do not expose arbitrary server text or credentials from libcurl's
         * diagnostic buffer. Report only an allowlisted timeout phase. */
        const char *phase = strstr(diagnostics, "server response timeout") ? " (attesa risposta SMTP)" :
            strstr(diagnostics, "Connection timed out") || strstr(diagnostics, "Connection timeout") ? " (connessione)" : "";
        return error_message(err, n, "Connessione SMTP non riuscita: %s%s (codice %d, risposta %ld).",
            curl_easy_strerror(result), phase, (int)result, response);
    }
    return 1;
}

static int smtp_send(const SmtpSettings *settings, const char *url,
                      const char *recipient, const char *message, size_t length,
                      char *err, size_t n)
{
    CURL *curl = curl_easy_init();
    if (!curl) return error_message(err, n, "Impossibile inizializzare il client SMTP.");
    struct curl_slist *recipients = curl_slist_append(NULL, recipient);
    if (!recipients) { curl_easy_cleanup(curl); return error_message(err, n, "Memoria insufficiente."); }
    Upload upload = { message, length, 0 };
    CURLcode result = smtp_options(curl, settings, url, 15L);
#define OPTION(option, value) do { if (result == CURLE_OK) result = curl_easy_setopt(curl, option, value); } while (0)
    OPTION(CURLOPT_MAIL_FROM, settings->from_email);
    OPTION(CURLOPT_MAIL_RCPT, recipients);
    OPTION(CURLOPT_READFUNCTION, upload_read);
    OPTION(CURLOPT_READDATA, &upload);
    OPTION(CURLOPT_UPLOAD, 1L);
    OPTION(CURLOPT_INFILESIZE_LARGE, (curl_off_t)length);
#undef OPTION
    if (result == CURLE_OK) result = curl_easy_perform(curl);
    long response = 0;
    (void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);
    if (result != CURLE_OK) return error_message(err, n, "Invio SMTP non riuscito: %s (codice %d, risposta %ld).",
        curl_easy_strerror(result), (int)result, response);
    return 1;
}

static int cleanup_queue(Store *store, int64_t now, char *err, size_t n)
{
    sqlite3_stmt *stmt = NULL;
    const char *recover = "UPDATE outbox SET status='failed',last_error='Invio interrotto: lease scaduta; esito da verificare.',"
        "next_attempt=? WHERE status='sending' AND next_attempt<=?";
    if (sqlite3_prepare_v2(store->db, recover, -1, &stmt, NULL) != SQLITE_OK) return db_error(store, err, n);
    int ok = sqlite3_bind_int64(stmt, 1, now) == SQLITE_OK &&
        sqlite3_bind_int64(stmt, 2, now) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_DONE;
    if (!ok) db_error(store, err, n);
    sqlite3_finalize(stmt);
    if (!ok) return 0;
    const char *prune = "DELETE FROM outbox WHERE status IN('pending','failed') AND NOT "
        DELIVERY_ELIGIBLE_SQL("?1");
    stmt = NULL;
    if (sqlite3_prepare_v2(store->db, prune, -1, &stmt, NULL) != SQLITE_OK) return db_error(store, err, n);
    ok = sqlite3_bind_int64(stmt, 1, now) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_DONE;
    if (!ok) db_error(store, err, n);
    sqlite3_finalize(stmt);
    return ok;
}

/* Claim with a compare-and-set UPDATE, committed before starting SMTP. */
static int claim(Store *store, int64_t now, int64_t *id, int *attempt,
                  char *err, size_t n)
{
    *id = 0;
    for (int retry = 0; retry < 10; ++retry) {
        sqlite3_stmt *stmt = NULL;
        const char *select = "SELECT id,attempts FROM outbox WHERE status IN('pending','failed') "
            "AND attempts<5 AND next_attempt<=?1 "
            "AND " DELIVERY_ELIGIBLE_SQL("?1") " AND " MONITOR_DELIVERY_READY_SQL("?1") " "
            "ORDER BY id LIMIT 1";
        if (sqlite3_prepare_v2(store->db, select, -1, &stmt, NULL) != SQLITE_OK) return db_error(store, err, n);
        if (sqlite3_bind_int64(stmt, 1, now) != SQLITE_OK) { db_error(store, err, n); sqlite3_finalize(stmt); return 0; }
        int result = sqlite3_step(stmt);
        if (result == SQLITE_DONE) { sqlite3_finalize(stmt); return 1; }
        if (result != SQLITE_ROW) { db_error(store, err, n); sqlite3_finalize(stmt); return 0; }
        int64_t candidate = sqlite3_column_int64(stmt, 0);
        int next_attempt = sqlite3_column_int(stmt, 1) + 1;
        sqlite3_finalize(stmt); stmt = NULL;
        const char *update = "UPDATE outbox SET status='sending',attempts=attempts+1,last_error='',next_attempt=? "
            "WHERE id=? AND status IN('pending','failed') AND attempts<5 AND next_attempt<=?3 AND attempts=?4 "
            "AND " DELIVERY_ELIGIBLE_SQL("?3") " AND " MONITOR_DELIVERY_READY_SQL("?3");
        if (sqlite3_prepare_v2(store->db, update, -1, &stmt, NULL) != SQLITE_OK) return db_error(store, err, n);
        int ok = sqlite3_bind_int64(stmt, 1, now + CLAIM_LEASE) == SQLITE_OK &&
            sqlite3_bind_int64(stmt, 2, candidate) == SQLITE_OK &&
            sqlite3_bind_int64(stmt, 3, now) == SQLITE_OK &&
            sqlite3_bind_int(stmt, 4, next_attempt - 1) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_DONE;
        int changed = sqlite3_changes(store->db);
        if (!ok) db_error(store, err, n);
        sqlite3_finalize(stmt);
        if (!ok) return 0;
        if (changed) { *id = candidate; *attempt = next_attempt; return 1; }
    }
    return 1;
}

static int finish(Store *store, int64_t id, int attempt, int64_t now,
                   int delivered, const char *failure, char *err, size_t n)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql = "UPDATE outbox SET status=?,last_error=?,sent_at=?,next_attempt=? "
        "WHERE id=? AND status='sending' AND attempts=? AND next_attempt=?";
    if (sqlite3_prepare_v2(store->db, sql, -1, &stmt, NULL) != SQLITE_OK) return db_error(store, err, n);
    int64_t retry_at = delivered ? 0 : now + (INT64_C(60) << (attempt - 1));
    int ok = bind_text(stmt, 1, delivered ? "sent" : "failed") &&
        bind_text(stmt, 2, delivered ? "" : failure) &&
        (delivered ? sqlite3_bind_int64(stmt, 3, now) : sqlite3_bind_null(stmt, 3)) == SQLITE_OK &&
        sqlite3_bind_int64(stmt, 4, retry_at) == SQLITE_OK &&
        sqlite3_bind_int64(stmt, 5, id) == SQLITE_OK &&
        sqlite3_bind_int(stmt, 6, attempt) == SQLITE_OK &&
        sqlite3_bind_int64(stmt, 7, now + CLAIM_LEASE) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_DONE;
    int changed = sqlite3_changes(store->db);
    if (!ok) db_error(store, err, n);
    sqlite3_finalize(stmt);
    if (!ok) return 0;
    return changed ? 1 : error_message(err, n, "Lease dell'invio email non più valida; verificare lo stato del messaggio.");
}

int delivery_process(Store *store, int64_t now, int *sent, char *err, size_t n)
{
    if (sent) *sent = 0;
    if (!valid_store(store, err, n)) return 0;
    if (!sqlite3_get_autocommit(store->db))
        return error_message(err, n, "Il worker email deve essere eseguito dopo il commit della transazione.");
    if (!cleanup_queue(store, now, err, n)) return 0;
    SmtpSettings settings = {0};
    /* A paused profile must not need its encryption key or credentials. */
    if (!smtp_settings_load(store, 0, &settings, err, n)) return 0;
    if (!settings.enabled) { smtp_settings_free(&settings); return 1; }
    smtp_settings_free(&settings);
    if (!smtp_settings_load(store, 1, &settings, err, n)) return 0;
    if (!settings.enabled) { smtp_settings_free(&settings); return 1; }
    if (!smtp_settings_validate(&settings, 1, err, n)) { smtp_settings_free(&settings); return 0; }
    char *url = smtp_settings_url(&settings, err, n);
    if (!url) { smtp_settings_free(&settings); return 0; }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        free(url); smtp_settings_free(&settings);
        return error_message(err, n, "Impossibile inizializzare il supporto SMTP.");
    }
    int ok = 1;
    char first_failure[512] = "";
    for (int batch = 0; batch < MAX_BATCH; ++batch) {
        int64_t id;
        int attempt;
        if (!claim(store, now, &id, &attempt, err, n)) { ok = 0; break; }
        if (!id) break;
        size_t length;
        char failure[512] = "";
        char *message = message_from(store, id, settings.from_email, &length, failure, sizeof failure);
        sqlite3_stmt *stmt = NULL;
        char *recipient = NULL;
        if (message && sqlite3_prepare_v2(store->db, "SELECT recipient_email FROM outbox WHERE id=?",
            -1, &stmt, NULL) == SQLITE_OK && sqlite3_bind_int64(stmt, 1, id) == SQLITE_OK &&
            sqlite3_step(stmt) == SQLITE_ROW) recipient = column_text(stmt, 0);
        sqlite3_finalize(stmt);
        int delivered = message && recipient && valid_email(recipient) ?
            smtp_send(&settings, url, recipient, message, length, failure, sizeof failure) : 0;
        if (!delivered && !failure[0]) error_message(failure, sizeof failure, "Destinatario o messaggio non disponibile.");
        free(recipient); free(message);
        if (!finish(store, id, attempt, now, delivered, failure, err, n)) { ok = 0; break; }
        if (delivered) { if (sent) ++*sent; }
        else {
            ok = 0;
            if (!first_failure[0]) (void)snprintf(first_failure, sizeof first_failure, "%s", failure);
        }
    }
    curl_global_cleanup();
    free(url); smtp_settings_free(&settings);
    if (!ok && first_failure[0]) error_message(err, n, "%s", first_failure);
    return ok;
}
