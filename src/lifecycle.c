#define _POSIX_C_SOURCE 200809L
#include "lifecycle.h"
#include "app.h"
#include "chain.h"
#include "operations.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <time.h>

static int db_error(Store *s, char *err, size_t n) {
    if (err && n) snprintf(err, n, "Errore archivio: %s", sqlite3_errmsg(s->db));
    return 0;
}

static int error(char *err, size_t n, const char *message) {
    if (err && n) snprintf(err, n, "%s", message);
    return 0;
}

static int step(Store *s, sqlite3_stmt **statement, char *err, size_t n) {
    int ok = sqlite3_step(*statement) == SQLITE_DONE;
    if (!ok) db_error(s, err, n);
    if (sqlite3_finalize(*statement) != SQLITE_OK && ok) ok = db_error(s, err, n);
    *statement = NULL;
    return ok;
}

static int prepare(Store *s, sqlite3_stmt **stmt, const char *sql, char *err, size_t n) {
    return sqlite3_prepare_v2(s->db, sql, -1, stmt, NULL) == SQLITE_OK || db_error(s, err, n);
}

static int bind_text(sqlite3_stmt *stmt, int col, const char *value) {
    return sqlite3_bind_text(stmt, col, value ? value : "", -1, SQLITE_TRANSIENT) == SQLITE_OK;
}

static int end_transaction(Store *s, const char *name, int ok, int outer, char *err, size_t n) {
    char command[128];
    if (ok) {
        snprintf(command, sizeof command, "RELEASE %s", name);
        ok = store_exec(s, command, err, n);
    }
    if (!ok) {
        if (outer) snprintf(command, sizeof command, "ROLLBACK");
        else snprintf(command, sizeof command, "ROLLBACK TO %s; RELEASE %s", name, name);
        sqlite3_exec(s->db, command, NULL, NULL, NULL);
    }
    return ok;
}

static int active_leaf(Store *s, int64_t id, char *err, size_t n) {
    sqlite3_stmt *stmt = NULL;
    if (!prepare(s, &stmt, "SELECT is_ca,archived FROM certificates WHERE id=?1", err, n)) return 0;
    sqlite3_bind_int64(stmt, 1, id);
    int rc = sqlite3_step(stmt);
    int ok = rc == SQLITE_ROW && !sqlite3_column_int(stmt, 0) && !sqlite3_column_int(stmt, 1);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) db_error(s, err, n);
    else if (!ok) error(err, n, "Seleziona un certificato finale non archiviato.");
    sqlite3_finalize(stmt);
    return ok;
}

int lifecycle_is_candidate(Store *s, int64_t old_id, int64_t new_id,
    int *matches, char *err, size_t n) {
    *matches = 0;
    if (old_id <= 0 || new_id <= 0 || old_id == new_id) return 1;
    sqlite3_stmt *stmt = NULL;
    if (!prepare(s, &stmt,
        "SELECT a.common_name,a.sans,a.not_after,a.archived,a.is_ca,b.common_name,b.sans,b.not_before,b.not_after,b.archived,b.is_ca "
        "FROM certificates a JOIN certificates b ON b.id=?2 WHERE a.id=?1", err, n)) return 0;
    sqlite3_bind_int64(stmt, 1, old_id); sqlite3_bind_int64(stmt, 2, new_id);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE || db_error(s, err, n);
    }
    int64_t now = (int64_t)time(NULL);
    if (!sqlite3_column_int(stmt, 3) && !sqlite3_column_int(stmt, 4) &&
        !sqlite3_column_int(stmt, 9) && !sqlite3_column_int(stmt, 10) &&
        sqlite3_column_int64(stmt, 7) <= now && sqlite3_column_int64(stmt, 8) > now &&
        sqlite3_column_int64(stmt, 8) > sqlite3_column_int64(stmt, 2)) {
        Certificate previous = {0}, next = {0};
        previous.common_name = (char *)sqlite3_column_text(stmt, 0);
        previous.sans = (char *)sqlite3_column_text(stmt, 1);
        next.common_name = (char *)sqlite3_column_text(stmt, 5);
        next.sans = (char *)sqlite3_column_text(stmt, 6);
        char mismatch[512] = "";
        *matches = chain_renewal_matches(&previous, &next, mismatch, sizeof mismatch);
    }
    sqlite3_finalize(stmt);
    return 1;
}

int lifecycle_set_plan(Store *s, int64_t job_id, int64_t old_id,
    const char *status, int64_t requested_at, int64_t renewal_at,
    int64_t install_at, const char *responsible, const char *notes,
    int64_t *saved_id, char *err, size_t n) {
    if (saved_id) *saved_id = 0;
    if (!status || (strcmp(status, "requested") && strcmp(status, "awaiting_ca") &&
        strcmp(status, "signed") && strcmp(status, "delivered") && strcmp(status, "installing")))
        return error(err, n, "Stato della pratica non valido.");
    if (job_id < 0 || old_id <= 0 || requested_at < 0 || renewal_at < 0 || install_at < 0 ||
        requested_at > INT64_C(253402300799) || renewal_at > INT64_C(253402300799) ||
        install_at > INT64_C(253402300799) || !responsible || !notes ||
        strlen(responsible) > 200 || strlen(notes) > 4000)
        return error(err, n, "Pianificazione non valida: controlla date, responsabile e note.");
    if (renewal_at && install_at && install_at < renewal_at)
        return error(err, n, "L'installazione pianificata non può precedere il rinnovo pianificato.");
    int64_t now = (int64_t)time(NULL);
    if (!requested_at) requested_at = now;
    int outer = sqlite3_get_autocommit(s->db);
    if (!store_exec(s, "SAVEPOINT lifecycle_plan", err, n)) return 0;
    sqlite3_stmt *stmt = NULL;
    int ok = 0;
    if (!active_leaf(s, old_id, err, n)) goto done;
    int has_new = 0;
    if (job_id) {
        if (!prepare(s, &stmt, "SELECT new_certificate_id,status FROM renewal_jobs WHERE id=?1 AND old_certificate_id=?2", err, n)) goto done;
        sqlite3_bind_int64(stmt, 1, job_id); sqlite3_bind_int64(stmt, 2, old_id);
        if (sqlite3_step(stmt) != SQLITE_ROW) { error(err, n, "Pratica di rinnovo non trovata."); goto done; }
        has_new = sqlite3_column_type(stmt, 0) != SQLITE_NULL;
        const char *old_status = (const char *)sqlite3_column_text(stmt, 1);
        if (!strcmp(old_status, "verified") || !strcmp(old_status, "retired")) {
            error(err, n, "La pratica è già chiusa."); goto done;
        }
        sqlite3_finalize(stmt); stmt = NULL;
    }
    if ((!strcmp(status, "signed") || !strcmp(status, "delivered") || !strcmp(status, "installing")) && !has_new) {
        error(err, n, "Collega il certificato firmato prima di avanzare la pratica."); goto done;
    }
    /* A linked replacement is already signed, even when an older plan form
       still submits a pre-signing status. Keep it approved for rollout. */
    if (has_new && (!strcmp(status, "requested") || !strcmp(status, "awaiting_ca")))
        status = "signed";
    const char *sql = job_id ?
        "UPDATE renewal_jobs SET status=?1,requested_at=?2,planned_renewal_at=nullif(?3,0),planned_install_at=nullif(?4,0),responsible=?5,notes=?6,updated_at=?7 WHERE id=?8" :
        "INSERT INTO renewal_jobs(status,requested_at,planned_renewal_at,planned_install_at,responsible,notes,updated_at,old_certificate_id,created_at) VALUES(?1,?2,nullif(?3,0),nullif(?4,0),?5,?6,?7,?8,?7)";
    if (!prepare(s, &stmt, sql, err, n)) goto done;
    if (!bind_text(stmt, 1, status) || sqlite3_bind_int64(stmt, 2, requested_at) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 3, renewal_at) != SQLITE_OK || sqlite3_bind_int64(stmt, 4, install_at) != SQLITE_OK ||
        !bind_text(stmt, 5, responsible) || !bind_text(stmt, 6, notes) || sqlite3_bind_int64(stmt, 7, now) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 8, job_id ? job_id : old_id) != SQLITE_OK) { db_error(s, err, n); goto done; }
    if (!step(s, &stmt, err, n)) goto done;
    if (!job_id) job_id = sqlite3_last_insert_rowid(s->db);
    ok = 1;
done:
    sqlite3_finalize(stmt);
    ok = end_transaction(s, "lifecycle_plan", ok, outer, err, n);
    if (ok && saved_id) *saved_id = job_id;
    return ok;
}

static int snapshot_endpoints(Store *s, int64_t job_id, int64_t old_id, char *err, size_t n) {
    sqlite3_stmt *stmt = NULL;
    if (!prepare(s, &stmt, "INSERT OR IGNORE INTO renewal_endpoints(job_id,monitor_id) SELECT ?1,id FROM monitors WHERE certificate_id=?2", err, n)) return 0;
    sqlite3_bind_int64(stmt, 1, job_id); sqlite3_bind_int64(stmt, 2, old_id);
    return step(s, &stmt, err, n);
}

int lifecycle_link_existing(Store *s, int64_t old_id, int64_t new_id,
    int64_t *job_id, int *queued, char *err, size_t n) {
    if (job_id) *job_id = 0;
    if (queued) *queued = 0;
    if (old_id <= 0 || new_id <= 0 || old_id == new_id)
        return error(err, n, "Collega due certificati distinti.");
    int outer = sqlite3_get_autocommit(s->db);
    if (!store_exec(s, "SAVEPOINT lifecycle_link", err, n)) return 0;
    sqlite3_stmt *stmt = NULL;
    int ok = 0, count = 0;
    int64_t id = 0, now = (int64_t)time(NULL);
    if (!prepare(s, &stmt,
        "SELECT a.common_name,a.sans,a.not_after,a.archived,a.is_ca,b.common_name,b.sans,b.not_before,b.not_after,b.archived,b.is_ca "
        "FROM certificates a JOIN certificates b ON b.id=?2 WHERE a.id=?1", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, old_id); sqlite3_bind_int64(stmt, 2, new_id);
    if (sqlite3_step(stmt) != SQLITE_ROW) { error(err, n, "Certificato precedente o nuovo non trovato."); goto done; }
    if (sqlite3_column_int(stmt, 3) || sqlite3_column_int(stmt, 4) ||
        sqlite3_column_int(stmt, 9) || sqlite3_column_int(stmt, 10)) {
        error(err, n, "Il rinnovo richiede due certificati finali non archiviati."); goto done;
    }
    if (sqlite3_column_int64(stmt, 7) > now || sqlite3_column_int64(stmt, 8) <= now ||
        sqlite3_column_int64(stmt, 8) <= sqlite3_column_int64(stmt, 2)) {
        error(err, n, "Il nuovo certificato deve essere già valido e avere una scadenza successiva."); goto done;
    }
    Certificate previous = {0}, next = {0};
    previous.common_name = (char *)sqlite3_column_text(stmt, 0);
    previous.sans = (char *)sqlite3_column_text(stmt, 1);
    next.common_name = (char *)sqlite3_column_text(stmt, 5);
    next.sans = (char *)sqlite3_column_text(stmt, 6);
    if (!chain_renewal_matches(&previous, &next, err, n)) goto done;
    sqlite3_finalize(stmt); stmt = NULL;
    /* Later expiry on every edge also prevents cycles in the renewal graph. */
    if (!prepare(s, &stmt, "SELECT id FROM renewal_jobs WHERE old_certificate_id=?1 AND new_certificate_id=?2", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, old_id); sqlite3_bind_int64(stmt, 2, new_id);
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) id = sqlite3_column_int64(stmt, 0);
    else if (rc != SQLITE_DONE) { db_error(s, err, n); goto done; }
    sqlite3_finalize(stmt); stmt = NULL;
    if (!id) {
        if (!prepare(s, &stmt, "SELECT id FROM renewal_jobs WHERE old_certificate_id=?1 AND new_certificate_id IS NULL AND status IN('requested','awaiting_ca') ORDER BY id LIMIT 1", err, n)) goto done;
        sqlite3_bind_int64(stmt, 1, old_id);
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) id = sqlite3_column_int64(stmt, 0);
        else if (rc != SQLITE_DONE) { db_error(s, err, n); goto done; }
        sqlite3_finalize(stmt); stmt = NULL;
        const char *sql = id ? "UPDATE renewal_jobs SET new_certificate_id=?2,status='signed',updated_at=?3 WHERE id=?4" :
            "INSERT INTO renewal_jobs(old_certificate_id,new_certificate_id,status,requested_at,created_at,updated_at) VALUES(?1,?2,'signed',?3,?3,?3)";
        if (!prepare(s, &stmt, sql, err, n)) goto done;
        sqlite3_bind_int64(stmt, 1, old_id); sqlite3_bind_int64(stmt, 2, new_id);
        sqlite3_bind_int64(stmt, 3, now);
        if (id) sqlite3_bind_int64(stmt, 4, id);
        if (!step(s, &stmt, err, n)) goto done;
        if (!id) id = sqlite3_last_insert_rowid(s->db);
    }
    if (!prepare(s, &stmt, "INSERT INTO contacts(certificate_id,role,name,email) SELECT ?1,role,name,email FROM contacts WHERE certificate_id=?2 ON CONFLICT(certificate_id,role,email) DO NOTHING", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, new_id); sqlite3_bind_int64(stmt, 2, old_id);
    if (!step(s, &stmt, err, n)) goto done;
    if (!prepare(s, &stmt, "INSERT OR IGNORE INTO certificate_groups(certificate_id,role,group_id) SELECT ?1,role,group_id FROM certificate_groups WHERE certificate_id=?2", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, new_id); sqlite3_bind_int64(stmt, 2, old_id);
    if (!step(s, &stmt, err, n)) goto done;
    if (!prepare(s, &stmt, "INSERT OR IGNORE INTO directory_assignments(certificate_id,role,person_id,group_id) SELECT ?1,role,person_id,group_id FROM directory_assignments WHERE certificate_id=?2", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, new_id); sqlite3_bind_int64(stmt, 2, old_id);
    if (!step(s, &stmt, err, n)) goto done;
    if (!prepare(s, &stmt, "SELECT count(*),coalesce(sum(role='technical'),0) FROM contacts WHERE certificate_id=?1", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, new_id);
    if (sqlite3_step(stmt) != SQLITE_ROW) { db_error(s, err, n); goto done; }
    int total = sqlite3_column_int(stmt, 0), technical = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt); stmt = NULL;
    if (total > 100) { error(err, n, "Il rinnovo unirebbe più di 100 referenti: riduci gli elenchi prima di riprovare."); goto done; }
    if (!prepare(s, &stmt, "INSERT OR IGNORE INTO reminder_policies(certificate_id,thresholds,escalation_email,escalation_name,escalation_after_days,enabled) SELECT ?1,thresholds,escalation_email,escalation_name,escalation_after_days,enabled FROM reminder_policies WHERE certificate_id=?2", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, new_id); sqlite3_bind_int64(stmt, 2, old_id);
    if (!step(s, &stmt, err, n)) goto done;
    if (!snapshot_endpoints(s, id, old_id, err, n)) goto done;
    if (technical && !app_distribute(s, new_id, &count, err, n)) goto done;
    ok = 1;
done:
    sqlite3_finalize(stmt);
    ok = end_transaction(s, "lifecycle_link", ok, outer, err, n);
    if (ok) { if (job_id) *job_id = id; if (queued) *queued = count; }
    return ok;
}

int lifecycle_request_install(Store *s, int64_t job_id, int64_t monitor_id,
    char *err, size_t n) {
    if (job_id <= 0 || monitor_id < 0) return error(err, n, "Pratica o servizio non valido.");
    int outer = sqlite3_get_autocommit(s->db);
    if (!store_exec(s, "SAVEPOINT lifecycle_install", err, n)) return 0;
    sqlite3_stmt *stmt = NULL;
    int ok = 0;
    int64_t old_id = 0, now = (int64_t)time(NULL);
    if (!prepare(s, &stmt, "SELECT j.old_certificate_id FROM renewal_jobs j JOIN certificates c ON c.id=j.new_certificate_id WHERE j.id=?1 AND j.status NOT IN('verified','retired') AND c.archived=0 AND c.not_before<=?2 AND c.not_after>?2", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, job_id); sqlite3_bind_int64(stmt, 2, now);
    if (sqlite3_step(stmt) != SQLITE_ROW) { error(err, n, "La pratica deve avere un nuovo certificato valido e non essere chiusa."); goto done; }
    old_id = sqlite3_column_int64(stmt, 0); sqlite3_finalize(stmt); stmt = NULL;
    if (!snapshot_endpoints(s, job_id, old_id, err, n)) goto done;
    if (!prepare(s, &stmt, "SELECT count(*),coalesce(sum(m.enabled=0),0) FROM renewal_endpoints e JOIN monitors m ON m.id=e.monitor_id WHERE e.job_id=?1 AND (?2=0 OR e.monitor_id=?2)", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, job_id); sqlite3_bind_int64(stmt, 2, monitor_id);
    if (sqlite3_step(stmt) != SQLITE_ROW) { db_error(s, err, n); goto done; }
    int total = sqlite3_column_int(stmt, 0), paused = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt); stmt = NULL;
    if (!total) { error(err, n, "La pratica non ha servizi da verificare: configura un URL oppure usa il ritiro manuale."); goto done; }
    if (paused) { error(err, n, "Riattiva i servizi in pausa prima di verificare l'installazione."); goto done; }
    if (!prepare(s, &stmt, "UPDATE renewal_endpoints SET verify_requested_at=?3,verified_at=NULL WHERE job_id=?1 AND (?2=0 OR monitor_id=?2)", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, job_id); sqlite3_bind_int64(stmt, 2, monitor_id); sqlite3_bind_int64(stmt, 3, now);
    if (!step(s, &stmt, err, n)) goto done;
    /* A worker already running at the time of the request cannot verify deployment. */
    if (!prepare(s, &stmt, "UPDATE monitors SET revision=revision+1,claim_until=0,next_check_at=?3,last_checked_at=NULL,last_status='pending',verified=0,updated_at=?3 WHERE id IN(SELECT monitor_id FROM renewal_endpoints WHERE job_id=?1 AND (?2=0 OR monitor_id=?2))", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, job_id); sqlite3_bind_int64(stmt, 2, monitor_id); sqlite3_bind_int64(stmt, 3, now);
    if (!step(s, &stmt, err, n)) goto done;
    if (!prepare(s, &stmt, "UPDATE renewal_jobs SET status='installing',updated_at=?2 WHERE id=?1", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, job_id); sqlite3_bind_int64(stmt, 2, now);
    ok = step(s, &stmt, err, n);
done:
    sqlite3_finalize(stmt);
    return end_transaction(s, "lifecycle_install", ok, outer, err, n);
}

int lifecycle_fingerprint_approved(Store *s, int64_t monitor_id,
    const char *fingerprint, int64_t now, int *approved, char *err, size_t n) {
    *approved = 0;
    if (!fingerprint || !*fingerprint) return 1;
    sqlite3_stmt *stmt = NULL;
    if (!prepare(s, &stmt,
        "SELECT EXISTS(SELECT 1 FROM monitors m JOIN renewal_jobs j ON j.old_certificate_id=m.certificate_id "
        "JOIN certificates c ON c.id=j.new_certificate_id WHERE m.id=?1 AND j.status IN('signed','delivered','installing') "
        "AND c.archived=0 AND c.not_before<=?3 AND c.not_after>?3 AND c.fingerprint=?2 COLLATE NOCASE)", err, n)) return 0;
    sqlite3_bind_int64(stmt, 1, monitor_id); bind_text(stmt, 2, fingerprint); sqlite3_bind_int64(stmt, 3, now);
    if (sqlite3_step(stmt) != SQLITE_ROW) { sqlite3_finalize(stmt); return db_error(s, err, n); }
    *approved = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return 1;
}

int lifecycle_record_monitor(Store *s, int64_t monitor_id, int64_t now,
    const char *fingerprint, int verified, char *err, size_t n) {
    sqlite3_stmt *stmt = NULL;
    if (!prepare(s, &stmt,
        "UPDATE renewal_endpoints SET last_match_at=CASE WHEN ?4=1 AND EXISTS(SELECT 1 FROM renewal_jobs j "
        "JOIN certificates c ON c.id=j.new_certificate_id WHERE j.id=job_id AND c.fingerprint=?3 COLLATE NOCASE "
        "AND c.not_before<=?2 AND c.not_after>?2 AND c.archived=0) THEN ?2 ELSE last_match_at END,"
        "verified_at=CASE WHEN ?4=1 AND verify_requested_at IS NOT NULL AND ?2>=verify_requested_at AND EXISTS("
        "SELECT 1 FROM renewal_jobs j JOIN certificates c ON c.id=j.new_certificate_id WHERE j.id=job_id "
        "AND c.fingerprint=?3 COLLATE NOCASE AND c.not_before<=?2 AND c.not_after>?2 AND c.archived=0) THEN ?2 ELSE NULL END "
        "WHERE monitor_id=?1 AND job_id IN(SELECT id FROM renewal_jobs WHERE status NOT IN('verified','retired'))", err, n)) return 0;
    sqlite3_bind_int64(stmt, 1, monitor_id); sqlite3_bind_int64(stmt, 2, now);
    bind_text(stmt, 3, fingerprint); sqlite3_bind_int(stmt, 4, verified ? 1 : 0);
    if (!step(s, &stmt, err, n)) return 0;
    if (!prepare(s, &stmt, "UPDATE renewal_jobs SET status='installing',updated_at=?2 WHERE status IN('signed','delivered') AND id IN(SELECT job_id FROM renewal_endpoints WHERE monitor_id=?1 AND last_match_at=?2)", err, n)) return 0;
    sqlite3_bind_int64(stmt, 1, monitor_id); sqlite3_bind_int64(stmt, 2, now);
    return step(s, &stmt, err, n);
}

static void reason(FILE *out, int *first, const char *code) {
    if (!out) return;
    if (!*first) fputc(',', out);
    *first = 0;
    app_json_string(out, code);
}

int lifecycle_checklist(Store *s, int64_t job_id, FILE *out,
    int *can_complete, char *err, size_t n) {
    if (can_complete) *can_complete = 0;
    sqlite3_stmt *q = NULL;
    int64_t now = (int64_t)time(NULL), old_id = 0, new_id = 0;
    int closed = 0, replacement_ok = 0, total = 0, blocked = 0, conflicts = 0;
    if (!prepare(s, &q, "SELECT j.old_certificate_id,coalesce(j.new_certificate_id,0),j.status,"
        "coalesce(c.archived=0 AND c.not_before<=?2 AND c.not_after>?2,0) "
        "FROM renewal_jobs j LEFT JOIN certificates c ON c.id=j.new_certificate_id WHERE j.id=?1", err, n)) return 0;
    sqlite3_bind_int64(q, 1, job_id); sqlite3_bind_int64(q, 2, now);
    if (sqlite3_step(q) != SQLITE_ROW) { sqlite3_finalize(q); return error(err, n, "Pratica di rinnovo non trovata."); }
    old_id = sqlite3_column_int64(q, 0); new_id = sqlite3_column_int64(q, 1);
    const char *status = (const char *)sqlite3_column_text(q, 2);
    closed = !strcmp(status, "verified") || !strcmp(status, "retired");
    replacement_ok = sqlite3_column_int(q, 3);
    sqlite3_finalize(q); q = NULL;
    if (!prepare(s, &q, "SELECT count(*) FROM monitors a JOIN monitors b ON a.target=b.target WHERE a.certificate_id=?1 AND b.certificate_id=?2", err, n)) return 0;
    sqlite3_bind_int64(q, 1, old_id); sqlite3_bind_int64(q, 2, new_id);
    if (sqlite3_step(q) != SQLITE_ROW) { sqlite3_finalize(q); return db_error(s, err, n); }
    conflicts = sqlite3_column_int(q, 0); sqlite3_finalize(q); q = NULL;
    if (out) fprintf(out, "{\"job_id\":%"PRId64",\"now\":%"PRId64",\"freshness_seconds\":900,\"endpoints\":[", job_id, now);
    if (!prepare(s, &q,
        "WITH ids AS (SELECT monitor_id FROM renewal_endpoints WHERE job_id=?1 UNION SELECT id FROM monitors WHERE certificate_id=?2) "
        "SELECT m.id,m.target,m.enabled,m.last_checked_at,m.last_status,m.verified,m.last_fingerprint,m.certificate_id,"
        "e.verify_requested_at,e.verified_at,c.fingerprint,"
        "EXISTS(SELECT 1 FROM monitors b WHERE b.target=m.target AND b.certificate_id=?3 AND m.certificate_id=?2),"
        "e.job_id IS NOT NULL FROM ids JOIN monitors m ON m.id=ids.monitor_id "
        "LEFT JOIN renewal_endpoints e ON e.monitor_id=m.id AND e.job_id=?1 "
        "LEFT JOIN certificates c ON c.id=?3 ORDER BY m.id", err, n)) return 0;
    sqlite3_bind_int64(q, 1, job_id); sqlite3_bind_int64(q, 2, old_id); sqlite3_bind_int64(q, 3, new_id);
    int rc;
    while ((rc = sqlite3_step(q)) == SQLITE_ROW) {
        int first = 1, failures = 0;
        int64_t requested = sqlite3_column_int64(q, 8), verified_at = sqlite3_column_int64(q, 9), checked = sqlite3_column_int64(q, 3);
        const char *observed = (const char *)sqlite3_column_text(q, 6), *expected = (const char *)sqlite3_column_text(q, 10);
        if (out) {
            if (total) fputc(',', out);
            fprintf(out, "{\"monitor_id\":%lld,\"target\":", (long long)sqlite3_column_int64(q, 0)); app_json_string(out, (const char *)sqlite3_column_text(q, 1));
            fprintf(out, ",\"enabled\":%s,\"certificate_id\":%lld,\"verify_requested_at\":", sqlite3_column_int(q,2)?"true":"false",(long long)sqlite3_column_int64(q,7));
            if (sqlite3_column_type(q,8)==SQLITE_NULL) fputs("null",out); else fprintf(out,"%"PRId64,requested);
            fputs(",\"verified_at\":",out); if(sqlite3_column_type(q,9)==SQLITE_NULL)fputs("null",out);else fprintf(out,"%"PRId64,verified_at);
            fputs(",\"last_checked_at\":",out); if(sqlite3_column_type(q,3)==SQLITE_NULL)fputs("null",out);else fprintf(out,"%"PRId64,checked);
            fputs(",\"last_status\":",out);app_json_string(out,(const char*)sqlite3_column_text(q,4));
            fputs(",\"expected_fingerprint\":",out);app_json_string(out,expected);
            fputs(",\"observed_fingerprint\":",out);app_json_string(out,observed);
            fputs(",\"reason_codes\":[",out);
        }
#define FAIL_IF(condition, code) do { if (condition) { failures++; reason(out, &first, code); } } while (0)
        FAIL_IF(!sqlite3_column_int(q,2), "service_paused");
        FAIL_IF(sqlite3_column_type(q,8)==SQLITE_NULL, "verification_not_requested");
        FAIL_IF(sqlite3_column_type(q,8)!=SQLITE_NULL && requested<now-900, "request_stale");
        FAIL_IF(sqlite3_column_type(q,9)==SQLITE_NULL, "installation_not_verified");
        FAIL_IF(sqlite3_column_type(q,9)!=SQLITE_NULL && verified_at<now-900, "proof_stale");
        FAIL_IF(sqlite3_column_type(q,9)!=SQLITE_NULL && sqlite3_column_type(q,8)!=SQLITE_NULL && verified_at<requested, "proof_before_request");
        FAIL_IF(sqlite3_column_type(q,3)==SQLITE_NULL, "service_not_checked");
        FAIL_IF(sqlite3_column_type(q,3)!=SQLITE_NULL && checked<now-900, "check_stale");
        FAIL_IF(sqlite3_column_type(q,3)!=SQLITE_NULL && sqlite3_column_type(q,8)!=SQLITE_NULL && checked<requested, "check_before_request");
        FAIL_IF(sqlite3_column_int(q,5)!=1, "tls_not_verified");
        FAIL_IF(strcmp((const char *)sqlite3_column_text(q,4),"ok"), "service_not_ok");
        FAIL_IF(!expected || !observed || strcasecmp(expected,observed), "fingerprint_mismatch");
        FAIL_IF(sqlite3_column_int64(q,7)!=old_id && sqlite3_column_int64(q,7)!=new_id, "association_changed");
        FAIL_IF(sqlite3_column_int(q,11), "duplicate_target");
#undef FAIL_IF
        if (out) fprintf(out, "],\"can_complete\":%s}", failures?"false":"true");
        total++; if (failures) blocked++;
    }
    sqlite3_finalize(q);
    if (rc != SQLITE_DONE) return db_error(s, err, n);
    int allowed = !closed && replacement_ok && total && !blocked && !conflicts;
    if (can_complete) *can_complete = allowed;
    if (out) {
        fprintf(out, "],\"endpoint_count\":%d,\"blocked_endpoint_count\":%d,\"duplicate_target_count\":%d,\"reason_codes\":[",total,blocked,conflicts);
        int first=1;
        if(closed) reason(out,&first,"job_closed");
        if(!new_id) reason(out,&first,"replacement_missing");
        else if(!replacement_ok) reason(out,&first,"replacement_not_valid");
        if(!total) reason(out,&first,"no_endpoints");
        if(blocked) reason(out,&first,"endpoint_checks_incomplete");
        if(conflicts) reason(out,&first,"duplicate_targets");
        fprintf(out,"],\"can_complete\":%s}",allowed?"true":"false");
    }
    return 1;
}

int lifecycle_finish(Store *s, int64_t job_id, char *err, size_t n) {
    int outer = sqlite3_get_autocommit(s->db);
    if (!store_exec(s, "SAVEPOINT lifecycle_finish", err, n)) return 0;
    sqlite3_stmt *stmt = NULL;
    int ok = 0;
    int64_t old_id = 0, new_id = 0, now = (int64_t)time(NULL);
    if (!prepare(s, &stmt, "SELECT j.old_certificate_id,j.new_certificate_id FROM renewal_jobs j JOIN certificates c ON c.id=j.new_certificate_id WHERE j.id=?1 AND j.status NOT IN('verified','retired') AND c.archived=0 AND c.not_before<=?2 AND c.not_after>?2", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, job_id); sqlite3_bind_int64(stmt, 2, now);
    if (sqlite3_step(stmt) != SQLITE_ROW) { error(err, n, "Pratica non trovata, già chiusa o nuovo certificato non valido."); goto done; }
    old_id = sqlite3_column_int64(stmt, 0); new_id = sqlite3_column_int64(stmt, 1);
    sqlite3_finalize(stmt); stmt = NULL;
    if (!snapshot_endpoints(s, job_id, old_id, err, n)) goto done;
    int can_complete = 0;
    if (!lifecycle_checklist(s, job_id, NULL, &can_complete, err, n)) goto done;
    if (!can_complete) {
        error(err, n, "Per chiudere ogni servizio deve confermare il nuovo certificato con una verifica TLS richiesta negli ultimi 15 minuti; risolvi anche eventuali URL duplicati."); goto done;
    }
    if (!operations_capture_report(s, job_id, "verified", err, n)) goto done;
    if (!prepare(s, &stmt, "UPDATE monitors SET certificate_id=?2,revision=revision+1,claim_until=0,updated_at=?3 WHERE certificate_id=?1 AND id IN(SELECT monitor_id FROM renewal_endpoints WHERE job_id=?4)", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, old_id); sqlite3_bind_int64(stmt, 2, new_id); sqlite3_bind_int64(stmt, 3, now); sqlite3_bind_int64(stmt, 4, job_id);
    if (!step(s, &stmt, err, n)) goto done;
    if (!prepare(s, &stmt, "UPDATE renewal_jobs SET status='verified',finished_at=?2,updated_at=?2 WHERE id=?1", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, job_id); sqlite3_bind_int64(stmt, 2, now);
    if (!step(s, &stmt, err, n)) goto done;
    if (!prepare(s, &stmt, "UPDATE certificates SET archived=1,superseded_by=?2 WHERE id=?1 AND NOT EXISTS(SELECT 1 FROM monitors WHERE certificate_id=?1)", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, old_id); sqlite3_bind_int64(stmt, 2, new_id);
    if (!step(s, &stmt, err, n)) goto done;
    if (!prepare(s, &stmt, "DELETE FROM outbox WHERE certificate_id=?1 AND status IN('pending','failed') AND EXISTS(SELECT 1 FROM certificates WHERE id=?1 AND archived=1)", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, old_id);
    ok = step(s, &stmt, err, n);
done:
    sqlite3_finalize(stmt);
    return end_transaction(s, "lifecycle_finish", ok, outer, err, n);
}

int lifecycle_retire(Store *s, int64_t job_id, char *err, size_t n) {
    int outer = sqlite3_get_autocommit(s->db);
    if (!store_exec(s, "SAVEPOINT lifecycle_retire", err, n)) return 0;
    sqlite3_stmt *stmt = NULL;
    int ok = 0;
    int64_t old_id = 0, new_id = 0, now = (int64_t)time(NULL);
    if (!prepare(s, &stmt, "SELECT old_certificate_id,coalesce(new_certificate_id,0),responsible,notes FROM renewal_jobs WHERE id=?1 AND status NOT IN('verified','retired')", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, job_id);
    if (sqlite3_step(stmt) != SQLITE_ROW) { error(err, n, "Pratica non trovata o già chiusa."); goto done; }
    old_id = sqlite3_column_int64(stmt, 0); new_id = sqlite3_column_int64(stmt, 1);
    const char *responsible = (const char *)sqlite3_column_text(stmt, 2), *notes = (const char *)sqlite3_column_text(stmt, 3);
    if (!responsible || !*responsible || !notes || !*notes) { error(err, n, "Il ritiro manuale richiede un responsabile e una nota esplicita."); goto done; }
    sqlite3_finalize(stmt); stmt = NULL;
    if (!prepare(s, &stmt, "SELECT count(*) FROM monitors WHERE certificate_id=?1", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, old_id);
    if (sqlite3_step(stmt) != SQLITE_ROW) { db_error(s, err, n); goto done; }
    int remaining = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt); stmt = NULL;
    if (remaining) { error(err, n, "Rimuovi o riassegna i servizi prima del ritiro manuale; anche i servizi in pausa restano associati."); goto done; }
    if (!operations_capture_report(s, job_id, "retired", err, n)) goto done;
    if (!prepare(s, &stmt, "UPDATE renewal_jobs SET status='retired',finished_at=?2,updated_at=?2 WHERE id=?1", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, job_id); sqlite3_bind_int64(stmt, 2, now);
    if (!step(s, &stmt, err, n)) goto done;
    if (!prepare(s, &stmt, "UPDATE certificates SET archived=1,superseded_by=nullif(?2,0) WHERE id=?1", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, old_id); sqlite3_bind_int64(stmt, 2, new_id);
    if (!step(s, &stmt, err, n)) goto done;
    if (!prepare(s, &stmt, "DELETE FROM outbox WHERE certificate_id=?1 AND status IN('pending','failed')", err, n)) goto done;
    sqlite3_bind_int64(stmt, 1, old_id);
    ok = step(s, &stmt, err, n);
done:
    sqlite3_finalize(stmt);
    return end_transaction(s, "lifecycle_retire", ok, outer, err, n);
}

static int json_rows(Store *s, FILE *out, const char *sql, char *err, size_t n) {
    sqlite3_stmt *stmt = NULL;
    if (!prepare(s, &stmt, sql, err, n)) return 0;
    int first = 1, rc;
    fputc('[', out);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (!first) fputc(',', out);
        first = 0;
        fputc('{', out);
        for (int i = 0; i < sqlite3_column_count(stmt); i++) {
            if (i) fputc(',', out);
            app_json_string(out, sqlite3_column_name(stmt, i));
            fputc(':', out);
            if (sqlite3_column_type(stmt, i) == SQLITE_NULL) fputs("null", out);
            else if (sqlite3_column_type(stmt, i) == SQLITE_INTEGER)
                fprintf(out, "%lld", (long long)sqlite3_column_int64(stmt, i));
            else app_json_string(out, (const char *)sqlite3_column_text(stmt, i));
        }
        fputc('}', out);
    }
    fputc(']', out);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE || db_error(s, err, n);
}

int lifecycle_state_append(Store *s, FILE *out, char *err, size_t n) {
    fputs(",\"renewal_jobs\":", out);
    if (!json_rows(s, out,
        "SELECT j.*,a.common_name AS old_common_name,a.fingerprint AS old_fingerprint,"
        "b.common_name AS new_common_name,b.fingerprint AS new_fingerprint,"
        "(SELECT count(*) FROM renewal_endpoints e WHERE e.job_id=j.id) AS endpoint_count,"
        "(SELECT count(*) FROM renewal_endpoints e WHERE e.job_id=j.id AND e.verified_at IS NOT NULL) AS verified_count "
        "FROM renewal_jobs j JOIN certificates a ON a.id=j.old_certificate_id "
        "LEFT JOIN certificates b ON b.id=j.new_certificate_id ORDER BY j.updated_at DESC,j.id DESC", err, n)) return 0;
    fputs(",\"renewal_endpoints\":", out);
    return json_rows(s, out,
        "SELECT e.*,m.certificate_id,m.target,m.enabled,m.last_status,m.last_checked_at,m.last_fingerprint,m.verified "
        "FROM renewal_endpoints e JOIN monitors m ON m.id=e.monitor_id ORDER BY e.job_id,e.monitor_id", err, n);
}
