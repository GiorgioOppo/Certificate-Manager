#define _POSIX_C_SOURCE 200809L
#include "app.h"
#include "chain.h"
#include "delivery.h"
#include "smtp_settings.h"
#include "lifecycle.h"
#include "workspace.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

volatile sig_atomic_t app_running = 1;

int64_t app_days_remaining(int64_t expiry, int64_t now) {
    int64_t diff = expiry - now;
    return diff > 0 ? diff / 86400 + (diff % 86400 != 0)
                    : diff / 86400 - (diff % 86400 != 0);
}

const char *app_status(int64_t start, int64_t expiry, int64_t now) {
    if (expiry <= now) return "expired";
    if (start > now) return "not_yet_valid";
    if (expiry - now <= 2 * INT64_C(86400)) return "urgent";
    if (expiry - now <= 45 * INT64_C(86400)) return "warning";
    return "healthy";
}

static int db_error(Store *s, char *err, size_t n) {
    snprintf(err, n, "Errore archivio: %s", sqlite3_errmsg(s->db));
    return 0;
}

int app_import(Store *s, const char *file, const char *source,
               int *imported, int *duplicates, char *err, size_t n) {
    CertificateList list = {0};
    *imported = *duplicates = 0;
    if (!certificate_load_file(file, &list, err, n)) return 0;
    if (!store_exec(s, "BEGIN IMMEDIATE", err, n)) {
        certificate_list_free(&list);
        return 0;
    }
    int ok = 1;
    for (size_t i = 0; i < list.count && ok; i++) {
        int inserted = 0;
        int64_t id = 0;
        ok = store_add(s, &list.items[i], source, (int64_t)time(NULL),
                       &id, &inserted, err, n);
        if (ok) {
            if (inserted) (*imported)++;
            else (*duplicates)++;
        }
    }
    certificate_list_free(&list);
    if (ok) ok = store_exec(s, "COMMIT", err, n);
    if (!ok) {
        sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
        *imported = *duplicates = 0;
    }
    return ok;
}

int app_check(Store *s, int64_t now, int *count, FILE *log,
              char *err, size_t n) {
    *count = 0;
    if (!store_exec(s, "BEGIN IMMEDIATE", err, n)) return 0;
    sqlite3_stmt *read = NULL, *write = NULL;
    char *messages = NULL;
    size_t messages_size = 0;
    FILE *buffer = open_memstream(&messages, &messages_size);
    if (!buffer) {
        snprintf(err, n, "Memoria insufficiente per i promemoria.");
        goto fail;
    }
    const char *sql = "INSERT INTO notifications(certificate_id,threshold,sent_at) "
        "SELECT ?1,?2,?3 WHERE NOT EXISTS (SELECT 1 FROM notifications "
        "WHERE certificate_id=?1 AND threshold<=?2)";
    if (sqlite3_prepare_v2(s->db, "SELECT id,common_name,not_after FROM certificates WHERE archived=0 "
                           "ORDER BY not_after,id", -1, &read, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(s->db, sql, -1, &write, NULL) != SQLITE_OK) {
        db_error(s, err, n);
        goto fail;
    }
    int rc;
    while ((rc = sqlite3_step(read)) == SQLITE_ROW) {
        int threshold = -1, escalated = 0;
        if (!reminder_policy_due(s, sqlite3_column_int64(read, 0), sqlite3_column_int64(read, 2),
                                 now, &threshold, err, n)) goto fail;
        if (threshold < 0) {
            if (!reminder_policy_check_escalation(s, sqlite3_column_int64(read, 0), now,
                                                   &escalated, err, n)) goto fail;
            continue;
        }
        sqlite3_reset(write);
        sqlite3_clear_bindings(write);
        if (sqlite3_bind_int64(write, 1, sqlite3_column_int64(read, 0)) != SQLITE_OK ||
            sqlite3_bind_int(write, 2, threshold) != SQLITE_OK ||
            sqlite3_bind_int64(write, 3, now) != SQLITE_OK ||
            sqlite3_step(write) != SQLITE_DONE) {
            db_error(s, err, n);
            goto fail;
        }
        if (sqlite3_changes(s->db)) {
            (*count)++;
            fprintf(buffer, "[PROMEMORIA %d giorni] %s — %s; giorni residui: %" PRId64 "\n",
                    threshold, (const char *)sqlite3_column_text(read, 1),
                    threshold == 0 ? "certificato scaduto" : "rinnovo da pianificare",
                    app_days_remaining(sqlite3_column_int64(read, 2), now));
        }
        if (!delivery_queue_expiry(s, sqlite3_column_int64(read, 0), threshold, now, err, n) ||
            !reminder_policy_check_escalation(s, sqlite3_column_int64(read, 0), now,
                                               &escalated, err, n)) goto fail;
    }
    if (rc != SQLITE_DONE) {
        db_error(s, err, n);
        goto fail;
    }
    sqlite3_finalize(read); read = NULL;
    sqlite3_finalize(write); write = NULL;
    int stream_ok = !ferror(buffer);
    if (fclose(buffer) != 0) stream_ok = 0;
    buffer = NULL;
    if (!stream_ok) {
        snprintf(err, n, "Impossibile preparare i promemoria.");
        goto fail;
    }
    if (!store_exec(s, "COMMIT", err, n)) goto fail;
    if (log && messages_size) {
        if (fwrite(messages, 1, messages_size, log) != messages_size || fflush(log) != 0)
            fprintf(stderr, "I promemoria sono salvati nell'archivio, ma la scrittura nel log non è riuscita.\n");
    }
    free(messages);
    return 1;
fail:
    sqlite3_finalize(read);
    sqlite3_finalize(write);
    if (buffer) fclose(buffer);
    free(messages);
    sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
    *count = 0;
    return 0;
}

int app_distribute(Store *s, int64_t id, int *queued, char *err, size_t n) {
    *queued = 0;
    if (!store_exec(s, "SAVEPOINT distribute", err, n)) return 0;
    sqlite3_stmt *stmt = NULL;
    CertificateChain chain = {0};
    int ok = 0;
    if (sqlite3_prepare_v2(s->db, "SELECT is_ca,archived,not_before,not_after FROM certificates WHERE id=?1",
                           -1, &stmt, NULL) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 1, id) != SQLITE_OK) {
        db_error(s, err, n); goto done;
    }
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        snprintf(err, n, "Certificato non trovato."); goto done;
    }
    int64_t now = (int64_t)time(NULL);
    if (sqlite3_column_int(stmt, 0) || sqlite3_column_int(stmt, 1) ||
        sqlite3_column_int64(stmt, 2) > now || sqlite3_column_int64(stmt, 3) <= now) {
        snprintf(err, n, "Per la consegna seleziona un certificato finale attuale, valido e non sostituito.");
        goto done;
    }
    sqlite3_finalize(stmt); stmt = NULL;
    if (!chain_describe(s, id, &chain, err, n)) goto done;
    if (!chain.pem_bundle || !*chain.pem_bundle) {
        snprintf(err, n, "Ricarica il certificato originale per renderlo disponibile come allegato.");
        goto done;
    }
    ok = delivery_queue_certificate(s, id, chain.pem_bundle, now, queued, err, n);
done:
    sqlite3_finalize(stmt);
    chain_free(&chain);
    if (ok) ok = store_exec(s, "RELEASE distribute", err, n);
    if (!ok) {
        sqlite3_exec(s->db, "ROLLBACK TO distribute; RELEASE distribute", NULL, NULL, NULL);
        *queued = 0;
    }
    return ok;
}

int app_renew(Store *s, int64_t old_id, const char *file, const char *source,
              int64_t *new_id, int *queued, char *err, size_t n) {
    *new_id = 0; *queued = 0;
    CertificateList list = {0};
    if (!certificate_load_file(file, &list, err, n)) return 0;
    Certificate *leaf = NULL;
    for (size_t i = 0; i < list.count; i++) {
        if (!list.items[i].is_ca) {
            if (leaf) {
                snprintf(err, n, "Il rinnovo deve contenere un solo certificato finale e le eventuali CA.");
                certificate_list_free(&list); return 0;
            }
            leaf = &list.items[i];
        }
    }
    int64_t now = (int64_t)time(NULL);
    if (!leaf || leaf->not_before > now || leaf->not_after <= now) {
        snprintf(err, n, "Carica un nuovo certificato finale già valido, con le eventuali CA della catena.");
        certificate_list_free(&list); return 0;
    }
    if (!store_exec(s, "BEGIN IMMEDIATE", err, n)) { certificate_list_free(&list); return 0; }
    int ok = 0;
    sqlite3_stmt *old = NULL;
    if (sqlite3_prepare_v2(s->db, "SELECT common_name,sans,not_after,archived,is_ca FROM certificates WHERE id=?1",
                           -1, &old, NULL) != SQLITE_OK || sqlite3_bind_int64(old, 1, old_id) != SQLITE_OK) {
        db_error(s, err, n); goto done;
    }
    if (sqlite3_step(old) != SQLITE_ROW) { snprintf(err, n, "Certificato precedente non trovato."); goto done; }
    if (sqlite3_column_int(old, 3) || sqlite3_column_int(old, 4)) {
        snprintf(err, n, "Il certificato precedente è una CA oppure è già stato sostituito."); goto done;
    }
    if (leaf->not_after <= sqlite3_column_int64(old, 2)) {
        snprintf(err, n, "Il rinnovo deve avere una scadenza successiva a quella precedente."); goto done;
    }
    Certificate previous = {0};
    previous.common_name = (char *)sqlite3_column_text(old, 0);
    previous.sans = (char *)sqlite3_column_text(old, 1);
    if (!chain_renewal_matches(&previous, leaf, err, n)) goto done;
    sqlite3_finalize(old); old = NULL;
    for (size_t i = 0; i < list.count; i++) {
        int64_t id; int inserted;
        if (!store_add(s, &list.items[i], source, now, &id, &inserted, err, n)) goto done;
        if (&list.items[i] == leaf) *new_id = id;
    }
    int64_t job_id = 0;
    if (!lifecycle_link_existing(s, old_id, *new_id, &job_id, queued, err, n)) goto done;
    ok = store_exec(s, "COMMIT", err, n);
done:
    sqlite3_finalize(old);
    certificate_list_free(&list);
    if (!ok) {
        sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
        *new_id = 0; *queued = 0;
    }
    return ok;
}

/* Keep valid UTF-8 intact; encode malformed filename bytes as JSON escapes. */
static size_t utf8_length(const unsigned char *p) {
    size_t length = p[0] >= 0xc2 && p[0] <= 0xdf ? 2 :
                    p[0] >= 0xe0 && p[0] <= 0xef ? 3 :
                    p[0] >= 0xf0 && p[0] <= 0xf4 ? 4 : 0;
    for (size_t i = 1; i < length; i++)
        if (!p[i] || p[i] < 0x80 || p[i] > 0xbf) return 0;
    if (length >= 3 && ((p[0] == 0xe0 && p[1] < 0xa0) ||
                       (p[0] == 0xed && p[1] > 0x9f))) return 0;
    if (length == 4 && ((p[0] == 0xf0 && p[1] < 0x90) ||
                       (p[0] == 0xf4 && p[1] > 0x8f))) return 0;
    return length;
}

void app_json_string(FILE *out, const char *value) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)(value ? value : ""); *p; p++) {
        switch (*p) {
            case '"': fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            case '\n': fputs("\\n", out); break;
            case '\r': fputs("\\r", out); break;
            case '\t': fputs("\\t", out); break;
            default:
                if (*p < 32 || *p == 127) fprintf(out, "\\u%04x", *p);
                else if (*p >= 128) {
                    size_t length = utf8_length(p);
                    if (!length) fprintf(out, "\\u%04x", *p);
                    else { fwrite(p, 1, length, out); p += length - 1; }
                } else fputc(*p, out);
        }
    }
    fputc('"', out);
}

static int json_rows(Store *s, FILE *out, const char *sql, int certs,
                     int64_t now, char *err, size_t n) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return db_error(s, err, n);
    int rc, first = 1;
    fputc('[', out);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (!first) fputc(',', out);
        first = 0;
        fputc('{', out);
        int64_t start = 0, expiry = 0, id = 0;
        for (int col = 0; col < sqlite3_column_count(stmt); col++) {
            const char *name = sqlite3_column_name(stmt, col);
            if (col) fputc(',', out);
            app_json_string(out, name);
            fputc(':', out);
            if (sqlite3_column_type(stmt, col) == SQLITE_NULL) fputs("null", out);
            else if (sqlite3_column_type(stmt, col) == SQLITE_INTEGER)
                fprintf(out, "%" PRId64, (int64_t)sqlite3_column_int64(stmt, col));
            else app_json_string(out, (const char *)sqlite3_column_text(stmt, col));
            if (!strcmp(name, "not_before")) start = sqlite3_column_int64(stmt, col);
            if (!strcmp(name, "not_after")) expiry = sqlite3_column_int64(stmt, col);
            if (!strcmp(name, "id")) id = sqlite3_column_int64(stmt, col);
        }
        if (certs) {
            fprintf(out, ",\"days_remaining\":%" PRId64 ",\"status\":",
                    app_days_remaining(expiry, now));
            app_json_string(out, app_status(start, expiry, now));
            CertificateChain chain = {0};
            if (!chain_describe(s, id, &chain, err, n)) { sqlite3_finalize(stmt); return 0; }
            fputs(",\"root_ca\":", out); app_json_string(out, chain.root_ca);
            fputs(",\"intermediate_ca\":", out); app_json_string(out, chain.intermediate_ca);
            fputs(",\"chain_status\":", out); app_json_string(out, chain.status);
            chain_free(&chain);
            sqlite3_stmt *contacts = NULL;
            if (sqlite3_prepare_v2(s->db, "SELECT role,name,email FROM contacts WHERE certificate_id=?1 ORDER BY role,name,email",
                                   -1, &contacts, NULL) != SQLITE_OK ||
                sqlite3_bind_int64(contacts, 1, id) != SQLITE_OK) {
                db_error(s, err, n); sqlite3_finalize(contacts); sqlite3_finalize(stmt); return 0;
            }
            fputs(",\"contacts\":[", out);
            int first_contact = 1, contact_rc;
            while ((contact_rc = sqlite3_step(contacts)) == SQLITE_ROW) {
                if (!first_contact) fputc(',', out);
                first_contact = 0;
                fputs("{\"role\":", out); app_json_string(out, (const char *)sqlite3_column_text(contacts, 0));
                fputs(",\"name\":", out); app_json_string(out, (const char *)sqlite3_column_text(contacts, 1));
                fputs(",\"email\":", out); app_json_string(out, (const char *)sqlite3_column_text(contacts, 2));
                fputc('}', out);
            }
            fputc(']', out);
            sqlite3_finalize(contacts);
            if (contact_rc != SQLITE_DONE) { db_error(s, err, n); sqlite3_finalize(stmt); return 0; }
        }
        fputc('}', out);
    }
    fputc(']', out);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return db_error(s, err, n);
    return 1;
}

static int json_smtp_settings(Store *s, FILE *out, char *err, size_t n) {
    SmtpSettings settings = {0};
    if (!smtp_settings_load(s, 0, &settings, err, n)) return 0;
    char validation[512] = "";
    int valid = smtp_settings_validate(&settings, settings.enabled ? 1 : 0, validation, sizeof validation);
    fprintf(out, ",\"smtp\":{\"exists\":%s,\"enabled\":%s,\"configured\":%s,\"port\":%d,"
                 "\"password_set\":%s,\"updated_at\":%" PRId64 ",\"source\":",
            settings.exists ? "true" : "false", settings.enabled ? "true" : "false",
            valid && settings.enabled ? "true" : "false", settings.port,
            settings.password_set ? "true" : "false", settings.updated_at);
    app_json_string(out, settings.source ? settings.source : "none");
    fputs(",\"host\":", out); app_json_string(out, settings.host);
    fputs(",\"security\":", out); app_json_string(out, settings.security);
    fputs(",\"from_email\":", out); app_json_string(out, settings.from_email);
    fputs(",\"username\":", out); app_json_string(out, settings.username);
    fputs(",\"error\":", out); app_json_string(out, valid ? "" : validation);
    fputc('}', out);
    smtp_settings_free(&settings);
    return 1;
}

char *app_state_json(Store *s, const char *token, size_t *length,
                     char *err, size_t n) {
    char *result = NULL;
    FILE *out = open_memstream(&result, length);
    if (!out) {
        snprintf(err, n, "Memoria insufficiente.");
        return NULL;
    }
    int64_t now = (int64_t)time(NULL);
    fputs("{\"csrf_token\":", out);
    app_json_string(out, token);
    fprintf(out, ",\"now\":%" PRId64 ",\"certificates\":", now);
    int ok = json_rows(s, out, "SELECT id,fingerprint,common_name,subject,issuer,serial,sans,key_algorithm,key_bits,"
                       "signature_algorithm,is_ca,not_before,not_after,source,added_at,archived,superseded_by,"
                       "(length(pem)>0) AS pem_available,CASE WHEN archived=1 THEN 'retired' "
                       "WHEN EXISTS(SELECT 1 FROM renewal_jobs j WHERE j.new_certificate_id=certificates.id AND j.status='installing') THEN 'deploying' "
                       "WHEN EXISTS(SELECT 1 FROM monitors m WHERE m.certificate_id=certificates.id) THEN 'in_use' "
                       "WHEN EXISTS(SELECT 1 FROM renewal_jobs j WHERE j.new_certificate_id=certificates.id AND j.status IN('signed','delivered')) THEN 'ready' "
                       "ELSE 'in_use' END AS operational_status FROM certificates ORDER BY not_after,id", 1, now, err, n);
    if (ok) {
        fputs(",\"notifications\":", out);
        ok = json_rows(s, out, "SELECT n.rowid AS id,n.certificate_id,n.threshold,n.sent_at,"
                       "c.common_name,c.not_after FROM notifications n JOIN certificates c "
                       "ON c.id=n.certificate_id ORDER BY n.sent_at DESC,n.rowid DESC LIMIT 200",
                       0, now, err, n);
    }
    if (ok) {
        fputs(",\"monitors\":", out);
        ok = json_rows(s, out, "SELECT m.*,c.common_name,c.fingerprint AS expected_fingerprint,c.archived "
                       "FROM monitors m JOIN certificates c ON c.id=m.certificate_id ORDER BY m.enabled DESC,m.id DESC",
                       0, now, err, n);
    }
    if (ok) {
        fputs(",\"monitor_events\":", out);
        ok = json_rows(s, out, "SELECT e.*,m.certificate_id,m.target,c.common_name FROM monitor_events e "
                       "JOIN monitors m ON m.id=e.monitor_id JOIN certificates c ON c.id=m.certificate_id "
                       "ORDER BY e.created_at DESC,e.id DESC LIMIT 200", 0, now, err, n);
    }
    if (ok) {
        sqlite3_stmt *counts = NULL;
        if (sqlite3_prepare_v2(s->db, "SELECT coalesce(sum(m.enabled=1 AND c.archived=0),0),"
                               "coalesce(sum(m.enabled=1 AND c.archived=0 AND m.last_status NOT IN('pending','ok')),0),"
                               "(SELECT count(*) FROM monitor_events WHERE acknowledged_at IS NULL),"
                               "coalesce(max(m.enabled=1 AND c.archived=0 AND m.claim_until>?1),0) "
                               "FROM monitors m JOIN certificates c ON c.id=m.certificate_id",
                               -1, &counts, NULL) != SQLITE_OK ||
            sqlite3_bind_int64(counts, 1, now) != SQLITE_OK || sqlite3_step(counts) != SQLITE_ROW) {
            db_error(s, err, n); ok = 0;
        } else {
            fprintf(out, ",\"monitoring\":{\"enabled\":%d,\"problems\":%d,\"unacknowledged\":%d,\"checking\":%s}",
                    sqlite3_column_int(counts, 0), sqlite3_column_int(counts, 1),
                    sqlite3_column_int(counts, 2), sqlite3_column_int(counts, 3) ? "true" : "false");
        }
        sqlite3_finalize(counts);
    }
    if (ok) {
        fputs(",\"outbox\":", out);
        ok = json_rows(s, out, "SELECT id,certificate_id,kind,recipient_name,recipient_email,threshold,subject,"
                       "status,attempts,last_error,created_at,sent_at,event_id,template_alert,template_audience,template_copy FROM outbox ORDER BY id DESC LIMIT 200",
                       0, now, err, n);
    }
    if (ok) {
        sqlite3_stmt *counts = NULL;
        if (sqlite3_prepare_v2(s->db, "SELECT coalesce(sum(status IN('pending','sending')),0),"
                               "coalesce(sum(status='failed'),0),coalesce(sum(status='sent'),0) FROM outbox",
                               -1, &counts, NULL) != SQLITE_OK || sqlite3_step(counts) != SQLITE_ROW) {
            db_error(s, err, n); ok = 0;
        } else {
            fprintf(out, ",\"delivery\":{\"configured\":%s,\"pending\":%d,\"failed\":%d,\"sent\":%d}",
                    delivery_is_configured(s) ? "true" : "false", sqlite3_column_int(counts, 0),
                    sqlite3_column_int(counts, 1), sqlite3_column_int(counts, 2));
        }
        sqlite3_finalize(counts);
    }
    if (ok) ok = json_smtp_settings(s, out, err, n);
    if (ok) ok = lifecycle_state_append(s, out, err, n);
    if (ok) ok = workspace_state_append(s, out, err, n);
    fputc('}', out);
    if (ferror(out)) ok = 0;
    if (fclose(out) != 0) ok = 0;
    if (!ok) {
        if (!err[0]) snprintf(err, n, "Impossibile generare lo stato dell'archivio.");
        free(result);
        return NULL;
    }
    return result;
}
