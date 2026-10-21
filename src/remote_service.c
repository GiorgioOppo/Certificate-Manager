#define _POSIX_C_SOURCE 200809L
#include "remote_service.h"
#include "remote.h"
#include "app.h"
#include <errno.h>
#include <inttypes.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SNAPSHOT_COUNT 8
#define SNAPSHOT_TTL_MS INT64_C(600000)
#define SNAPSHOT_MEMORY (32U * 1024U * 1024U)

typedef struct {
    char token[33];
    char *pem, *source, *fingerprint;
    size_t length;
    int64_t created;
} Snapshot;

static Snapshot snapshots[SNAPSHOT_COUNT];

static int64_t tick_ms(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return 0;
    return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static void snapshot_free(Snapshot *snapshot) {
    free(snapshot->pem); free(snapshot->source); free(snapshot->fingerprint);
    memset(snapshot, 0, sizeof *snapshot);
}

void remote_cache_clear(void) {
    for (size_t i = 0; i < SNAPSHOT_COUNT; i++) snapshot_free(&snapshots[i]);
}

static void expire_snapshots(void) {
    int64_t now = tick_ms();
    for (size_t i = 0; i < SNAPSHOT_COUNT; i++)
        if (snapshots[i].pem && now - snapshots[i].created >= SNAPSHOT_TTL_MS)
            snapshot_free(&snapshots[i]);
}

static Snapshot *snapshot_find(const char *token) {
    if (!token || strlen(token) != 32) return NULL;
    expire_snapshots();
    for (size_t i = 0; i < SNAPSHOT_COUNT; i++)
        if (snapshots[i].pem && !strcmp(snapshots[i].token, token)) return &snapshots[i];
    return NULL;
}

const char *remote_snapshot_pem(const char *token, size_t *length) {
    Snapshot *snapshot = snapshot_find(token);
    if (!snapshot) return NULL;
    *length = snapshot->length;
    return snapshot->pem;
}

const char *remote_snapshot_target(const char *token) {
    Snapshot *snapshot = snapshot_find(token);
    return snapshot ? snapshot->source : NULL;
}

static Snapshot *snapshot_save(const RemoteResult *remote, char *err, size_t n) {
    if (!remote->pem_bundle || !*remote->pem_bundle || !remote->certificates.count) return NULL;
    size_t length = strlen(remote->pem_bundle);
    if (length > SNAPSHOT_MEMORY) { snprintf(err, n, "Catena ricevuta troppo grande."); return NULL; }
    char *pem = strdup(remote->pem_bundle);
    char *source = strdup(remote->target ? remote->target : "certificato HTTPS remoto");
    char *fingerprint = strdup(remote->certificates.items[0].fingerprint);
    unsigned char random[16];
    if (!pem || !source || !fingerprint || RAND_bytes(random, sizeof random) != 1) {
        free(pem); free(source); free(fingerprint);
        snprintf(err, n, "Impossibile conservare temporaneamente il certificato ricevuto."); return NULL;
    }
    expire_snapshots();
    Snapshot *slot = NULL;
    for (;;) {
        size_t total = 0;
        Snapshot *oldest = NULL;
        slot = NULL;
        for (size_t i = 0; i < SNAPSHOT_COUNT; i++) {
            if (!snapshots[i].pem) { if (!slot) slot = &snapshots[i]; }
            else {
                total += snapshots[i].length;
                if (!oldest || snapshots[i].created < oldest->created) oldest = &snapshots[i];
            }
        }
        if (slot && total + length <= SNAPSHOT_MEMORY) break;
        if (!oldest) { free(pem); free(source); free(fingerprint); snprintf(err, n, "Cache temporanea non disponibile."); return NULL; }
        snapshot_free(oldest);
    }
    slot->pem = pem; slot->source = source; slot->fingerprint = fingerprint;
    slot->length = length; slot->created = tick_ms();
    for (size_t i = 0; i < sizeof random; i++) snprintf(slot->token + i * 2, 3, "%02x", random[i]);
    return slot;
}

static void json_certificate(FILE *out, const Certificate *cert) {
    fputs("{\"common_name\":", out); app_json_string(out, cert->common_name);
    fputs(",\"subject\":", out); app_json_string(out, cert->subject);
    fputs(",\"issuer\":", out); app_json_string(out, cert->issuer);
    fputs(",\"serial\":", out); app_json_string(out, cert->serial);
    fputs(",\"sans\":", out); app_json_string(out, cert->sans);
    fputs(",\"fingerprint\":", out); app_json_string(out, cert->fingerprint);
    fputs(",\"key_algorithm\":", out); app_json_string(out, cert->key_algorithm);
    fputs(",\"signature_algorithm\":", out); app_json_string(out, cert->signature_algorithm);
    fprintf(out, ",\"key_bits\":%d,\"is_ca\":%d,\"not_before\":%" PRId64 ",\"not_after\":%" PRId64 "}",
            cert->key_bits, cert->is_ca, cert->not_before, cert->not_after);
}

char *remote_check_json(Store *store, const char *target, int64_t expected_id,
                        size_t *length, int *status, char *err, size_t n) {
    *status = 400;
    char *expected_fingerprint = NULL;
    if (expected_id) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(store->db, "SELECT fingerprint FROM certificates WHERE id=?1", -1, &stmt, NULL) != SQLITE_OK ||
            sqlite3_bind_int64(stmt, 1, expected_id) != SQLITE_OK) {
            snprintf(err, n, "Errore archivio: %s", sqlite3_errmsg(store->db));
            sqlite3_finalize(stmt); *status = 500; return NULL;
        }
        int rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) expected_fingerprint = strdup((const char *)sqlite3_column_text(stmt, 0));
        else snprintf(err, n, "Certificato da confrontare non trovato.");
        sqlite3_finalize(stmt);
        if (!expected_fingerprint) { if (!err[0]) snprintf(err, n, "Memoria insufficiente."); return NULL; }
    }
    RemoteResult remote = {0};
    if (!remote_fetch(target, &remote, err, n)) {
        free(expected_fingerprint); remote_result_free(&remote); return NULL;
    }
    *status = 500;
    Snapshot *snapshot = NULL;
    if (remote.tls_ok && remote.certificates.count) {
        snapshot = snapshot_save(&remote, err, n);
        if (!snapshot) { remote_result_free(&remote); free(expected_fingerprint); return NULL; }
    }
    char *json = NULL;
    FILE *out = open_memstream(&json, length);
    if (!out) {
        snprintf(err, n, "Memoria insufficiente.");
        remote_result_free(&remote); free(expected_fingerprint); return NULL;
    }
    fputs("{\"ok\":true,\"target\":", out); app_json_string(out, remote.target);
    fputs(",\"host\":", out); app_json_string(out, remote.host);
    fputs(",\"address\":", out); app_json_string(out, remote.address);
    fputs(",\"tls_version\":", out); app_json_string(out, remote.tls_version);
    fputs(",\"verification_error\":", out); app_json_string(out, remote.verification_error);
    fprintf(out, ",\"port\":%d,\"checked_at\":%" PRId64 ",\"dns_ok\":%s,\"tcp_ok\":%s,\"tls_ok\":%s,"
            "\"chain_trusted\":%s,\"hostname_valid\":%s,\"time_valid\":%s,\"verified\":%s,\"expected_certificate_id\":",
            remote.port, remote.checked_at, remote.dns_ok ? "true" : "false", remote.tcp_ok ? "true" : "false",
            remote.tls_ok ? "true" : "false", remote.chain_trusted ? "true" : "false",
            remote.hostname_valid ? "true" : "false", remote.time_valid ? "true" : "false", remote.verified ? "true" : "false");
    if (expected_id) fprintf(out, "%" PRId64, expected_id); else fputs("null", out);
    fputs(",\"comparison\":", out);
    app_json_string(out, expected_fingerprint && remote.certificates.count ?
        (!strcmp(expected_fingerprint, remote.certificates.items[0].fingerprint) ? "same" : "changed") : "unknown");
    fputs(",\"token\":", out);
    if (snapshot) app_json_string(out, snapshot->token); else fputs("null", out);
    fputs(",\"download_url\":", out);
    if (snapshot) {
        char url[96]; snprintf(url, sizeof url, "/api/remote/%s/download", snapshot->token);
        app_json_string(out, url);
    } else fputs("null", out);
    fputs(",\"certificate\":", out);
    if (remote.certificates.count) json_certificate(out, &remote.certificates.items[0]); else fputs("null", out);
    fputs(",\"presented_chain\":[", out);
    for (size_t i = 0; i < remote.certificates.count; i++) {
        if (i) fputc(',', out);
        json_certificate(out, &remote.certificates.items[i]);
    }
    fputs("]}", out);
    int ok = !ferror(out);
    if (fclose(out)) ok = 0;
    remote_result_free(&remote); free(expected_fingerprint);
    if (!ok) { free(json); snprintf(err, n, "Impossibile preparare il risultato del controllo."); return NULL; }
    *status = 200;
    return json;
}

int remote_import_snapshot(Store *store, const char *token, int *imported,
                            int *duplicates, int64_t *certificate_id, char *err, size_t n) {
    *imported = *duplicates = 0; *certificate_id = 0;
    Snapshot *snapshot = snapshot_find(token);
    if (!snapshot) { snprintf(err, n, "Certificato temporaneo scaduto o non trovato: ripeti la verifica online."); return 0; }
    char temporary[] = "/tmp/certificati-remote-XXXXXX";
    int fd = mkstemp(temporary);
    if (fd < 0) { snprintf(err, n, "Impossibile preparare il certificato per l'importazione."); return 0; }
    size_t written = 0;
    int ok = 1;
    while (written < snapshot->length) {
        ssize_t count = write(fd, snapshot->pem + written, snapshot->length - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ok = 0; break; }
        written += (size_t)count;
    }
    if (close(fd)) ok = 0;
    if (ok) ok = app_import(store, temporary, snapshot->source, imported, duplicates, err, n);
    unlink(temporary);
    if (!ok) { if (!err[0]) snprintf(err, n, "Impossibile importare il certificato ricevuto."); return 0; }
    sqlite3_stmt *stmt = NULL;
    ok = sqlite3_prepare_v2(store->db, "SELECT id FROM certificates WHERE fingerprint=?1", -1, &stmt, NULL) == SQLITE_OK &&
         sqlite3_bind_text(stmt, 1, snapshot->fingerprint, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
         sqlite3_step(stmt) == SQLITE_ROW;
    if (ok) *certificate_id = sqlite3_column_int64(stmt, 0);
    else snprintf(err, n, "Certificato importato, ma impossibile recuperarne l'identificativo.");
    sqlite3_finalize(stmt);
    return ok;
}
