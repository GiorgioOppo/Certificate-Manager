#define _POSIX_C_SOURCE 200809L
#include "monitor.h"
#include "delivery.h"
#include "lifecycle.h"
#include "incident.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MONITOR_MAX_COUNT 100
#define MONITOR_DEFAULT_INTERVAL 900
#define MONITOR_WORKER_TIMEOUT_MS 15000
#define MONITOR_LEASE_SECONDS 30
#define MONITOR_SUMMARY_MAGIC UINT32_C(0x4d4f4e31)

/* Implemented by the remote module; normalization performs no network I/O. */
int remote_normalize_target(const char *input, char **canonical, char *err, size_t errlen);

typedef struct {
    uint32_t magic;
    int local_error;
    int dns_ok;
    int tcp_ok;
    int tls_ok;
    int verified;
    int has_certificate;
    char fingerprint[128];
    char address[128];
    char message[1024];
} WorkerSummary;

typedef struct {
    int active;
    pid_t pid;
    int fd;
    Store *store;
    int64_t id;
    int64_t revision;
    int64_t lease;
    int64_t deadline_ms;
    size_t received;
    int finished;
    WorkerSummary summary;
} Worker;

static Worker worker = {.fd = -1};

static void error_text(char *err, size_t size, const char *message)
{
    if (err != NULL && size != 0)
        (void)snprintf(err, size, "%s", message);
}

static int database_error(Store *store, char *err, size_t size)
{
    error_text(err, size, sqlite3_errmsg(store->db));
    return 0;
}

static void rollback_savepoint(Store *store, const char *name, int outer)
{
    if (outer) {
        (void)sqlite3_exec(store->db, "ROLLBACK", NULL, NULL, NULL);
    } else {
        char sql[160];
        (void)snprintf(sql, sizeof sql, "ROLLBACK TO %s; RELEASE %s", name, name);
        (void)sqlite3_exec(store->db, sql, NULL, NULL, NULL);
    }
}

static int valid_store(Store *store, char *err, size_t size)
{
    if (store == NULL || store->db == NULL) {
        error_text(err, size, "Archivio non aperto.");
        return 0;
    }
    return 1;
}

static int valid_now(int64_t now)
{
    return now >= 0 && now <= INT64_MAX - 86400;
}

static int bind_text(sqlite3_stmt *statement, int index, const char *value)
{
    return sqlite3_bind_text(statement, index, value != NULL ? value : "", -1,
                              SQLITE_TRANSIENT) == SQLITE_OK;
}

static char *duplicate(const char *value)
{
    size_t size = strlen(value);
    char *copy = malloc(size + 1);
    if (copy != NULL)
        memcpy(copy, value, size + 1);
    return copy;
}

static int scalar(Store *store, const char *sql, int64_t id, int *value)
{
    sqlite3_stmt *statement = NULL;
    int ok = sqlite3_prepare_v2(store->db, sql, -1, &statement, NULL) == SQLITE_OK;
    if (ok && sqlite3_bind_parameter_count(statement) != 0)
        ok = sqlite3_bind_int64(statement, 1, id) == SQLITE_OK;
    if (ok) ok = sqlite3_step(statement) == SQLITE_ROW;
    if (ok) *value = sqlite3_column_int(statement, 0);
    if (sqlite3_finalize(statement) != SQLITE_OK) ok = 0;
    return ok;
}

static int64_t monotonic_ms(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return -1;
    return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static void kill_worker(void)
{
    if (worker.pid > 0) {
        /* The resolver fork made by remote_fetch inherits this process group. */
        (void)kill(-worker.pid, SIGKILL);
        (void)kill(worker.pid, SIGKILL);
        while (waitpid(worker.pid, NULL, 0) < 0 && errno == EINTR) {}
        worker.pid = 0;
    }
    if (worker.fd >= 0) {
        close(worker.fd);
        worker.fd = -1;
    }
}

static void clear_worker(void)
{
    kill_worker();
    memset(&worker, 0, sizeof(worker));
    worker.fd = -1;
}

int monitor_save(Store *store, int64_t id, int64_t certificate_id,
                  const char *target, int interval_seconds, int enabled,
                  int64_t now, int64_t *saved_id, char *err, size_t errlen)
{
    char *canonical = NULL;
    sqlite3_stmt *statement = NULL;
    int count;
    int ok = 0;
    int outer = 0;
    int64_t result_id = id;
    error_text(err, errlen, "");
    if (saved_id != NULL) *saved_id = 0;
    if (!valid_store(store, err, errlen))
        return 0;
    if (interval_seconds == 0) interval_seconds = MONITOR_DEFAULT_INTERVAL;
    if (id < 0 || certificate_id <= 0 || interval_seconds < 60 || interval_seconds > 86400 ||
        (enabled != 0 && enabled != 1) || !valid_now(now)) {
        error_text(err, errlen, "Configurazione monitor non valida: intervallo da 60 a 86400 secondi.");
        return 0;
    }
    if (!remote_normalize_target(target, &canonical, err, errlen))
        return 0;
    outer = sqlite3_get_autocommit(store->db);
    if (!store_exec(store, "SAVEPOINT monitor_save", err, errlen))
        goto done;
    if (!scalar(store, "SELECT count(*) FROM certificates WHERE id=? AND is_ca=0 AND archived=0",
                certificate_id, &count))
        goto database_failure;
    if (count == 0) {
        error_text(err, errlen, "Seleziona un certificato finale attuale e non sostituito.");
        goto failure;
    }
    if (id == 0) {
        if (!scalar(store, "SELECT count(*) FROM monitors", 0, &count))
            goto database_failure;
        if (count >= MONITOR_MAX_COUNT) {
            error_text(err, errlen, "E possibile configurare al massimo 100 monitor.");
            goto failure;
        }
        if (sqlite3_prepare_v2(store->db,
            "INSERT INTO monitors(certificate_id,target,interval_seconds,enabled,next_check_at,created_at,updated_at) "
            "VALUES(?1,?2,?3,?4,?5,?5,?5)", -1, &statement, NULL) != SQLITE_OK)
            goto database_failure;
    } else {
        if (!scalar(store, "SELECT count(*) FROM monitors WHERE id=?", id, &count))
            goto database_failure;
        if (count == 0) {
            error_text(err, errlen, "Monitor non trovato.");
            goto failure;
        }
        if (sqlite3_prepare_v2(store->db,
            "DELETE FROM outbox WHERE kind='monitor' AND status IN('pending','failed') "
            "AND event_id IN(SELECT id FROM monitor_events WHERE monitor_id=?1) "
            "AND EXISTS(SELECT 1 FROM monitors WHERE id=?1 AND (certificate_id<>?2 OR target<>?3))",
            -1, &statement, NULL) != SQLITE_OK ||
            sqlite3_bind_int64(statement, 1, id) != SQLITE_OK ||
            sqlite3_bind_int64(statement, 2, certificate_id) != SQLITE_OK || !bind_text(statement, 3, canonical) ||
            sqlite3_step(statement) != SQLITE_DONE) goto database_failure;
        sqlite3_finalize(statement); statement = NULL;
        if (sqlite3_prepare_v2(store->db,
            "UPDATE monitor_options SET consecutive_failures=0,incident_open=0,raw_event_id=NULL,last_alert_event_id=NULL "
            "WHERE monitor_id=?1 AND EXISTS(SELECT 1 FROM monitors WHERE id=?1 AND (certificate_id<>?2 OR target<>?3))",
            -1, &statement, NULL) != SQLITE_OK ||
            sqlite3_bind_int64(statement, 1, id) != SQLITE_OK ||
            sqlite3_bind_int64(statement, 2, certificate_id) != SQLITE_OK || !bind_text(statement, 3, canonical) ||
            sqlite3_step(statement) != SQLITE_DONE) goto database_failure;
        sqlite3_finalize(statement); statement = NULL;
        if (sqlite3_prepare_v2(store->db,
            "UPDATE monitors SET certificate_id=?1,target=?2,interval_seconds=?3,enabled=?4,"
            "revision=revision+1,next_check_at=?5,claim_until=0,updated_at=?5,"
            "last_checked_at=CASE WHEN certificate_id<>?1 OR target<>?2 THEN NULL ELSE last_checked_at END,"
            "last_status=CASE WHEN certificate_id<>?1 OR target<>?2 THEN 'pending' ELSE last_status END,"
            "last_error=CASE WHEN certificate_id<>?1 OR target<>?2 THEN '' ELSE last_error END,"
            "last_fingerprint=CASE WHEN certificate_id<>?1 OR target<>?2 THEN '' ELSE last_fingerprint END,"
            "last_address=CASE WHEN certificate_id<>?1 OR target<>?2 THEN '' ELSE last_address END,"
            "dns_ok=CASE WHEN certificate_id<>?1 OR target<>?2 THEN 0 ELSE dns_ok END,"
            "tcp_ok=CASE WHEN certificate_id<>?1 OR target<>?2 THEN 0 ELSE tcp_ok END,"
            "tls_ok=CASE WHEN certificate_id<>?1 OR target<>?2 THEN 0 ELSE tls_ok END,"
            "verified=CASE WHEN certificate_id<>?1 OR target<>?2 THEN 0 ELSE verified END WHERE id=?6",
            -1, &statement, NULL) != SQLITE_OK)
            goto database_failure;
    }
    if (sqlite3_bind_int64(statement, 1, certificate_id) != SQLITE_OK ||
        !bind_text(statement, 2, canonical) ||
        sqlite3_bind_int(statement, 3, interval_seconds) != SQLITE_OK ||
        sqlite3_bind_int(statement, 4, enabled) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 5, now) != SQLITE_OK ||
        (id != 0 && sqlite3_bind_int64(statement, 6, id) != SQLITE_OK) ||
        sqlite3_step(statement) != SQLITE_DONE)
        goto database_failure;
    if (id == 0) result_id = sqlite3_last_insert_rowid(store->db);
    if (sqlite3_finalize(statement) != SQLITE_OK) {
        statement = NULL;
        goto database_failure;
    }
    statement = NULL;
    if (!store_exec(store, "RELEASE monitor_save", err, errlen))
        goto failure;
    if (saved_id != NULL) *saved_id = result_id;
    if (worker.active && worker.store == store && worker.id == result_id)
        clear_worker();
    ok = 1;
    goto done;
database_failure:
    if (sqlite3_extended_errcode(store->db) == SQLITE_CONSTRAINT_UNIQUE)
        error_text(err, errlen, "Questo URL e gia associato al certificato.");
    else
        (void)database_error(store, err, errlen);
failure:
    sqlite3_finalize(statement);
    statement = NULL;
    rollback_savepoint(store, "monitor_save", outer);
done:
    sqlite3_finalize(statement);
    free(canonical);
    return ok;
}

int monitor_request(Store *store, int64_t id, int64_t now,
                     char *err, size_t errlen)
{
    sqlite3_stmt *statement = NULL;
    error_text(err, errlen, "");
    if (!valid_store(store, err, errlen)) return 0;
    if (id <= 0 || !valid_now(now)) {
        error_text(err, errlen, "Monitor o data non validi.");
        return 0;
    }
    if (sqlite3_prepare_v2(store->db,
        "UPDATE monitors SET next_check_at=?1,updated_at=?1 WHERE id=?2 AND enabled=1 AND "
        "EXISTS(SELECT 1 FROM certificates c WHERE c.id=monitors.certificate_id AND c.archived=0 AND c.is_ca=0)",
        -1, &statement, NULL) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 1, now) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 2, id) != SQLITE_OK || sqlite3_step(statement) != SQLITE_DONE) {
        (void)database_error(store, err, errlen);
        sqlite3_finalize(statement);
        return 0;
    }
    int changed = sqlite3_changes(store->db);
    if (sqlite3_finalize(statement) != SQLITE_OK)
        return database_error(store, err, errlen);
    if (!changed) {
        error_text(err, errlen, "Monitor non trovato, in pausa o associato a un certificato sostituito.");
        return 0;
    }
    return 1;
}

int monitor_remove(Store *store, int64_t id, char *err, size_t errlen)
{
    sqlite3_stmt *statement = NULL;
    error_text(err, errlen, "");
    if (!valid_store(store, err, errlen)) return 0;
    if (id <= 0) {
        error_text(err, errlen, "Monitor non valido.");
        return 0;
    }
    if (sqlite3_prepare_v2(store->db, "DELETE FROM monitors WHERE id=?", -1,
        &statement, NULL) != SQLITE_OK || sqlite3_bind_int64(statement, 1, id) != SQLITE_OK ||
        sqlite3_step(statement) != SQLITE_DONE) {
        (void)database_error(store, err, errlen);
        sqlite3_finalize(statement);
        return 0;
    }
    int changed = sqlite3_changes(store->db);
    if (sqlite3_finalize(statement) != SQLITE_OK)
        return database_error(store, err, errlen);
    if (!changed) {
        error_text(err, errlen, "Monitor non trovato.");
        return 0;
    }
    if (worker.active && worker.store == store && worker.id == id)
        clear_worker();
    return 1;
}

static int fingerprint_equal(const char *a, const char *b)
{
    for (;;) {
        unsigned char ca;
        unsigned char cb;
        while (*a == ':') ++a;
        while (*b == ':') ++b;
        ca = (unsigned char)*a;
        cb = (unsigned char)*b;
        if (ca >= 'a' && ca <= 'z') ca = (unsigned char)(ca - 32);
        if (cb >= 'a' && cb <= 'z') cb = (unsigned char)(cb - 32);
        if (ca != cb) return 0;
        if (ca == 0) return 1;
        ++a; ++b;
    }
}

static const char *result_fingerprint(const RemoteResult *result)
{
    if (result != NULL && result->tls_ok && result->certificates.count != 0 &&
        result->certificates.items != NULL && result->certificates.items[0].fingerprint != NULL)
        return result->certificates.items[0].fingerprint;
    return "";
}

static int apply_result(Store *store, int64_t monitor_id, int64_t revision,
                        int64_t lease, int64_t now, const RemoteResult *result,
                        int local_error, const char *local_message, char *err, size_t errlen)
{
    sqlite3_stmt *statement = NULL;
    char *target = NULL;
    char *expected = NULL;
    char *previous_status = NULL;
    char *previous_fingerprint = NULL;
    const char *observed = local_error ? "" : result_fingerprint(result);
    const char *status;
    const char *detail;
    int interval;
    int approved = 0;
    int ok = 0;
    int outer = 0;
    int rc;
    char message[2048];
    error_text(err, errlen, "");
    if (!valid_store(store, err, errlen)) return 0;
    if (monitor_id <= 0 || revision <= 0 || !valid_now(now) || (!local_error && result == NULL)) {
        error_text(err, errlen, "Risultato del monitor non valido.");
        return 0;
    }
    outer = sqlite3_get_autocommit(store->db);
    if (!store_exec(store, "SAVEPOINT monitor_result", err, errlen))
        return 0;
    if (sqlite3_prepare_v2(store->db,
        "SELECT m.target,m.interval_seconds,m.last_status,m.last_fingerprint,c.fingerprint FROM monitors m "
        "JOIN certificates c ON c.id=m.certificate_id WHERE m.id=?1 AND m.revision=?2 AND m.enabled=1 "
        "AND c.archived=0 AND c.is_ca=0 AND (?3=0 OR m.claim_until=?3)",
        -1, &statement, NULL) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 1, monitor_id) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 2, revision) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 3, lease) != SQLITE_OK)
        goto database_failure;
    rc = sqlite3_step(statement);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(statement); statement = NULL;
        /* Clear only our own obsolete lease, never a replacement worker's. */
        if (lease != 0) {
            if (sqlite3_prepare_v2(store->db,
                "UPDATE monitors SET claim_until=0 WHERE id=?1 AND revision=?2 AND claim_until=?3", -1,
                &statement, NULL) != SQLITE_OK ||
                sqlite3_bind_int64(statement, 1, monitor_id) != SQLITE_OK ||
                sqlite3_bind_int64(statement, 2, revision) != SQLITE_OK ||
                sqlite3_bind_int64(statement, 3, lease) != SQLITE_OK || sqlite3_step(statement) != SQLITE_DONE)
                goto database_failure;
            sqlite3_finalize(statement); statement = NULL;
        }
        ok = store_exec(store, "RELEASE monitor_result", err, errlen);
        if (!ok) goto failure;
        goto done;
    }
    if (rc != SQLITE_ROW)
        goto database_failure;
    target = duplicate((const char *)sqlite3_column_text(statement, 0));
    interval = sqlite3_column_int(statement, 1);
    previous_status = duplicate((const char *)sqlite3_column_text(statement, 2));
    previous_fingerprint = duplicate((const char *)sqlite3_column_text(statement, 3));
    expected = duplicate((const char *)sqlite3_column_text(statement, 4));
    sqlite3_finalize(statement); statement = NULL;
    if (target == NULL || previous_status == NULL || previous_fingerprint == NULL || expected == NULL) {
        error_text(err, errlen, "Memoria insufficiente per aggiornare il monitor.");
        goto failure;
    }
    if (observed[0] && !fingerprint_equal(expected, observed) &&
        !lifecycle_fingerprint_approved(store, monitor_id, observed, now,
                                         &approved, err, errlen)) goto failure;
    detail = local_error ? (local_message != NULL ? local_message : "Errore locale non specificato.") :
        (result->verification_error != NULL ? result->verification_error : "");
    if (local_error) {
        status = "error";
        (void)snprintf(message, sizeof(message), "Controllo di %s non completato per un errore locale. %s", target, detail);
    } else if (!result->dns_ok || !result->tcp_ok) {
        status = "unreachable";
        (void)snprintf(message, sizeof(message), "Il servizio %s non e raggiungibile. %s", target, detail);
    } else if (!result->tls_ok || observed[0] == '\0') {
        status = "tls_error";
        (void)snprintf(message, sizeof(message), "Il servizio %s risponde TCP, ma il certificato HTTPS non e disponibile. %s", target, detail);
    } else if (!fingerprint_equal(expected, observed) && !approved) {
        status = "changed";
        (void)snprintf(message, sizeof(message), "Il certificato servito da %s differisce da quello registrato. %s", target, detail);
    } else if (!result->verified) {
        status = "verification_error";
        (void)snprintf(message, sizeof(message), "Il certificato servito da %s coincide con quello registrato, ma non supera la verifica TLS. %s", target, detail);
    } else {
        status = "ok";
        message[0] = '\0';
    }
    if (sqlite3_prepare_v2(store->db,
        "UPDATE monitors SET last_checked_at=?1,last_status=?2,last_error=?3,"
        "last_fingerprint=CASE WHEN ?4<>'' THEN ?4 ELSE last_fingerprint END,last_address=?5,"
        "dns_ok=?6,tcp_ok=?7,tls_ok=?8,verified=?9,next_check_at=?10,claim_until=0,updated_at=?1 "
        "WHERE id=?11 AND revision=?12", -1, &statement, NULL) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 1, now) != SQLITE_OK || !bind_text(statement, 2, status) ||
        !bind_text(statement, 3, message) || !bind_text(statement, 4, observed) ||
        !bind_text(statement, 5, !local_error && result->address != NULL ? result->address : "") ||
        sqlite3_bind_int(statement, 6, !local_error && result->dns_ok) != SQLITE_OK ||
        sqlite3_bind_int(statement, 7, !local_error && result->tcp_ok) != SQLITE_OK ||
        sqlite3_bind_int(statement, 8, !local_error && result->tls_ok) != SQLITE_OK ||
        sqlite3_bind_int(statement, 9, !local_error && result->verified) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 10, now + interval) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 11, monitor_id) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 12, revision) != SQLITE_OK || sqlite3_step(statement) != SQLITE_DONE)
        goto database_failure;
    sqlite3_finalize(statement); statement = NULL;
    /* Revision/lease checks above reject probes started before an installation
     * request. Only fresh, fully verified observations can confirm a rollout. */
    if (!lifecycle_record_monitor(store, monitor_id, now, observed,
        !local_error && result->verified && !strcmp(status, "ok"), err, errlen)) goto failure;
    if (!strcmp(status, "ok"))
        (void)snprintf(message, sizeof(message), "Il servizio %s e di nuovo raggiungibile e presenta il certificato registrato, verificato.", target);
    if (!incident_record(store, monitor_id, now, status, previous_status,
        expected, observed, previous_fingerprint, message, err, errlen)) goto failure;
    ok = store_exec(store, "RELEASE monitor_result", err, errlen);
    if (!ok) goto failure;
    goto done;
database_failure:
    (void)database_error(store, err, errlen);
failure:
    sqlite3_finalize(statement); statement = NULL;
    rollback_savepoint(store, "monitor_result", outer);
done:
    sqlite3_finalize(statement);
    free(target); free(expected); free(previous_status); free(previous_fingerprint);
    return ok;
}

int monitor_record_result(Store *store, int64_t monitor_id, int64_t revision,
                           int64_t now, const RemoteResult *result,
                           int local_error, const char *local_message,
                           char *err, size_t errlen)
{
    return apply_result(store, monitor_id, revision, 0, now, result, local_error,
                         local_message, err, errlen);
}

static void child_probe(int fd, const char *target)
{
    WorkerSummary summary;
    RemoteResult result = {0};
    char error[1024] = "";
    size_t written = 0;
    long max_fd = sysconf(_SC_OPEN_MAX);
    memset(&summary, 0, sizeof(summary));
    summary.magic = MONITOR_SUMMARY_MAGIC;
    if (setpgid(0, 0) != 0) {
        summary.local_error = 1;
        (void)snprintf(summary.message, sizeof(summary.message), "Impossibile isolare il processo di controllo.");
    } else {
        /* The worker never accesses SQLite or retains the web listener. */
        if (max_fd < 0) max_fd = 1024;
        for (long candidate = 3; candidate < max_fd; ++candidate)
            if (candidate != fd) close((int)candidate);
        int ok = remote_fetch(target, &result, error, sizeof(error));
        summary.local_error = !ok;
        summary.dns_ok = result.dns_ok;
        summary.tcp_ok = result.tcp_ok;
        summary.tls_ok = result.tls_ok;
        summary.verified = result.verified;
        summary.has_certificate = result_fingerprint(&result)[0] != '\0';
        (void)snprintf(summary.fingerprint, sizeof(summary.fingerprint), "%s", result_fingerprint(&result));
        (void)snprintf(summary.address, sizeof(summary.address), "%s", result.address != NULL ? result.address : "");
        (void)snprintf(summary.message, sizeof(summary.message), "%s",
            !ok ? error : result.verification_error != NULL ? result.verification_error : "");
        remote_result_free(&result);
    }
    while (written < sizeof(summary)) {
        ssize_t count = write(fd, (const unsigned char *)&summary + written, sizeof(summary) - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        written += (size_t)count;
    }
    close(fd);
    _exit(written == sizeof(summary) ? 0 : 1);
}

static void set_worker_error(const char *message)
{
    memset(&worker.summary, 0, sizeof(worker.summary));
    worker.summary.magic = MONITOR_SUMMARY_MAGIC;
    worker.summary.local_error = 1;
    (void)snprintf(worker.summary.message, sizeof(worker.summary.message), "%s", message);
    worker.received = sizeof(worker.summary);
    worker.finished = 1;
}

static void read_worker(void)
{
    while (worker.fd >= 0 && worker.received < sizeof(worker.summary)) {
        ssize_t count = read(worker.fd, (unsigned char *)&worker.summary + worker.received,
                             sizeof(worker.summary) - worker.received);
        if (count > 0) worker.received += (size_t)count;
        else if (count < 0 && errno == EINTR) continue;
        else break;
    }
}

static int finish_worker(Store *store, int64_t now, char *err, size_t errlen)
{
    int64_t tick = monotonic_ms();
    if (!worker.finished) {
        read_worker();
        int child_status;
        pid_t status = waitpid(worker.pid, &child_status, WNOHANG);
        if (status == worker.pid) {
            (void)kill(-worker.pid, SIGKILL);
            worker.pid = 0;
            read_worker();
            if (worker.fd >= 0) close(worker.fd);
            worker.fd = -1;
            worker.finished = 1;
            if (worker.received != sizeof(worker.summary) || worker.summary.magic != MONITOR_SUMMARY_MAGIC)
                set_worker_error("Il processo di controllo si e interrotto senza un risultato completo.");
        } else if (status < 0 && errno != EINTR) {
            kill_worker();
            set_worker_error("Impossibile leggere l'esito del processo di controllo.");
        } else if (tick < 0 || tick >= worker.deadline_ms) {
            kill_worker();
            if (worker.received != sizeof(worker.summary) || worker.summary.magic != MONITOR_SUMMARY_MAGIC)
                set_worker_error("Il controllo remoto ha superato il limite massimo di 15 secondi.");
            worker.finished = 1;
        }
    }
    if (!worker.finished)
        return 1;
    Certificate certificate = {0};
    RemoteResult result = {0};
    certificate.fingerprint = worker.summary.fingerprint;
    result.dns_ok = worker.summary.dns_ok;
    result.tcp_ok = worker.summary.tcp_ok;
    result.tls_ok = worker.summary.tls_ok;
    result.verified = worker.summary.verified;
    result.address = worker.summary.address;
    result.verification_error = worker.summary.message;
    result.certificates.items = &certificate;
    result.certificates.count = worker.summary.has_certificate ? 1 : 0;
    if (!apply_result(store, worker.id, worker.revision, worker.lease, now, &result,
        worker.summary.local_error, worker.summary.message, err, errlen))
        return 0; /* Keep the completed summary and retry if SQLite is busy. */
    clear_worker();
    return 1;
}

static int start_due(Store *store, int64_t now, char *err, size_t errlen)
{
    int outer = sqlite3_get_autocommit(store->db);
    sqlite3_stmt *statement = NULL;
    char *target = NULL;
    int64_t id = 0;
    int64_t revision = 0;
    int ok = 0;
    int rc;
    int pipe_fds[2] = {-1, -1};
    if (!store_exec(store, "SAVEPOINT monitor_claim", err, errlen))
        return 0;
    if (sqlite3_prepare_v2(store->db,
        "SELECT m.id,m.revision,m.target FROM monitors m JOIN certificates c ON c.id=m.certificate_id "
        "WHERE m.enabled=1 AND c.archived=0 AND c.is_ca=0 AND m.next_check_at<=?1 AND m.claim_until<=?1 "
        "ORDER BY m.next_check_at,m.id LIMIT 1", -1, &statement, NULL) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 1, now) != SQLITE_OK)
        goto database_failure;
    rc = sqlite3_step(statement);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(statement); statement = NULL;
        ok = store_exec(store, "RELEASE monitor_claim", err, errlen);
        if (!ok) goto failure;
        goto done;
    }
    if (rc != SQLITE_ROW)
        goto database_failure;
    id = sqlite3_column_int64(statement, 0);
    revision = sqlite3_column_int64(statement, 1);
    target = duplicate((const char *)sqlite3_column_text(statement, 2));
    sqlite3_finalize(statement); statement = NULL;
    if (target == NULL) {
        error_text(err, errlen, "Memoria insufficiente per avviare il monitor.");
        goto failure;
    }
    if (sqlite3_prepare_v2(store->db,
        "UPDATE monitors SET claim_until=?1 WHERE id=?2 AND revision=?3 AND enabled=1 AND claim_until<=?4",
        -1, &statement, NULL) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 1, now + MONITOR_LEASE_SECONDS) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 2, id) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 3, revision) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 4, now) != SQLITE_OK || sqlite3_step(statement) != SQLITE_DONE)
        goto database_failure;
    int changed = sqlite3_changes(store->db);
    sqlite3_finalize(statement); statement = NULL;
    if (!store_exec(store, "RELEASE monitor_claim", err, errlen))
        goto failure;
    if (!changed) { ok = 1; goto done; }
    memset(&worker, 0, sizeof(worker));
    worker.active = 1;
    worker.fd = -1;
    worker.store = store;
    worker.id = id;
    worker.revision = revision;
    worker.lease = now + MONITOR_LEASE_SECONDS;
    int64_t tick = monotonic_ms();
    worker.deadline_ms = tick >= 0 ? tick + MONITOR_WORKER_TIMEOUT_MS : 0;
    if (tick < 0 || pipe(pipe_fds) != 0 ||
        fcntl(pipe_fds[0], F_SETFL, O_NONBLOCK) != 0 ||
        fcntl(pipe_fds[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(pipe_fds[1], F_SETFD, FD_CLOEXEC) != 0) {
        if (pipe_fds[0] >= 0) close(pipe_fds[0]);
        if (pipe_fds[1] >= 0) close(pipe_fds[1]);
        set_worker_error("Impossibile creare il canale del processo di controllo.");
        ok = finish_worker(store, now, err, errlen);
        goto done;
    }
    worker.pid = fork();
    if (worker.pid == 0) {
        close(pipe_fds[0]);
        child_probe(pipe_fds[1], target);
    }
    close(pipe_fds[1]);
    if (worker.pid < 0) {
        worker.pid = 0;
        close(pipe_fds[0]);
        set_worker_error("Impossibile avviare il processo di controllo.");
        ok = finish_worker(store, now, err, errlen);
        goto done;
    }
    (void)setpgid(worker.pid, worker.pid);
    worker.fd = pipe_fds[0];
    ok = 1;
    goto done;
database_failure:
    (void)database_error(store, err, errlen);
failure:
    sqlite3_finalize(statement); statement = NULL;
    rollback_savepoint(store, "monitor_claim", outer);
done:
    sqlite3_finalize(statement);
    free(target);
    return ok;
}

int monitor_tick(Store *store, int64_t now, char *err, size_t errlen)
{
    int timeout = 5000;
    int ok;
    error_text(err, errlen, "");
    if (!valid_store(store, err, errlen)) return 0;
    if (!valid_now(now)) {
        error_text(err, errlen, "Data del controllo monitor non valida.");
        return 0;
    }
    if (!sqlite3_get_autocommit(store->db))
        return 1; /* Run after the caller commits its request transaction. */
    if (worker.active && worker.store != store) {
        error_text(err, errlen, "Un monitor e gia attivo per un altro archivio.");
        return 0;
    }
    if (!scalar(store, "PRAGMA busy_timeout", 0, &timeout))
        return database_error(store, err, errlen);
    (void)sqlite3_busy_timeout(store->db, 0);
    ok = incident_tick(store, now, err, errlen);
    if (ok && worker.active) {
        int current = 0;
        sqlite3_stmt *revision_check = NULL;
        int read_ok = sqlite3_prepare_v2(store->db,
            "SELECT revision FROM monitors WHERE id=?", -1, &revision_check, NULL) == SQLITE_OK &&
            sqlite3_bind_int64(revision_check, 1, worker.id) == SQLITE_OK;
        if (read_ok) {
            int rc = sqlite3_step(revision_check);
            if (rc == SQLITE_ROW)
                current = sqlite3_column_int64(revision_check, 0) == worker.revision;
            else if (rc != SQLITE_DONE) read_ok = 0;
        }
        sqlite3_finalize(revision_check);
        if (!read_ok) ok = database_error(store, err, errlen);
        else if (!current) clear_worker();
    }
    if (ok) ok = !worker.active || finish_worker(store, now, err, errlen);
    if (ok && !worker.active)
        ok = start_due(store, now, err, errlen);
    (void)sqlite3_busy_timeout(store->db, timeout);
    return ok;
}

void monitor_shutdown(void)
{
    if (!worker.active)
        return;
    kill_worker();
    if (worker.store != NULL && worker.store->db != NULL) {
        sqlite3_stmt *statement = NULL;
        int timeout = 5000;
        (void)scalar(worker.store, "PRAGMA busy_timeout", 0, &timeout);
        (void)sqlite3_busy_timeout(worker.store->db, 0);
        if (sqlite3_prepare_v2(worker.store->db,
            "UPDATE monitors SET claim_until=0 WHERE id=?1 AND revision=?2 AND claim_until=?3",
            -1, &statement, NULL) == SQLITE_OK &&
            sqlite3_bind_int64(statement, 1, worker.id) == SQLITE_OK &&
            sqlite3_bind_int64(statement, 2, worker.revision) == SQLITE_OK &&
            sqlite3_bind_int64(statement, 3, worker.lease) == SQLITE_OK)
            (void)sqlite3_step(statement);
        sqlite3_finalize(statement);
        (void)sqlite3_busy_timeout(worker.store->db, timeout);
    }
    clear_worker();
}
