#define _POSIX_C_SOURCE 200809L
#include "app.h"
#include "chain.h"
#include "delivery.h"
#include "monitor.h"
#include "smtp_settings.h"
#include "remote_service.h"
#include "assets.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MAX_HEADERS 16384
#define MAX_BODY (16U * 1024U * 1024U)

typedef struct {
    char method[16], target[256], host[128], origin[256], csrf[128], filename[1024], content_type[128];
    size_t length;
    int has_length, has_origin;
    unsigned char *body;
} Request;

static int send_all(int fd, const void *data, size_t length) {
    const unsigned char *p = data;
    while (length && app_running) {
        ssize_t sent = send(fd, p, length, 0);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) return 0;
        p += sent;
        length -= (size_t)sent;
    }
    return length == 0;
}

static void response_extended(int fd, int code, const char *type, const void *body, size_t length, const char *filename) {
    const char *reason = "OK";
    switch (code) {
        case 400: reason = "Bad Request"; break;
        case 403: reason = "Forbidden"; break;
        case 404: reason = "Not Found"; break;
        case 405: reason = "Method Not Allowed"; break;
        case 408: reason = "Request Timeout"; break;
        case 413: reason = "Content Too Large"; break;
        case 431: reason = "Request Header Fields Too Large"; break;
        case 500: reason = "Internal Server Error"; break;
        case 502: reason = "Bad Gateway"; break;
    }
    char header[2048];
    char disposition[256] = "";
    if (filename) snprintf(disposition, sizeof disposition, "Content-Disposition: attachment; filename=\"%s\"\r\n", filename);
    int count = snprintf(header, sizeof header,
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
        "%sConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
        "Referrer-Policy: no-referrer\r\nCross-Origin-Resource-Policy: same-origin\r\n"
        "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'\r\n\r\n", code, reason, type, length, disposition);
    if (count > 0 && (size_t)count < sizeof header && send_all(fd, header, (size_t)count))
        send_all(fd, body, length);
}

static void response(int fd, int code, const char *type, const void *body, size_t length) {
    response_extended(fd, code, type, body, length, NULL);
}

static void json_error(int fd, int status, const char *message) {
    char *body = NULL;
    size_t length = 0;
    FILE *out = open_memstream(&body, &length);
    if (!out) {
        const char fallback[] = "{\"error\":\"Memoria insufficiente\"}";
        response(fd, 500, "application/json; charset=utf-8", fallback, sizeof fallback - 1);
        return;
    }
    fputs("{\"error\":", out);
    app_json_string(out, message);
    fputc('}', out);
    if (fclose(out) == 0) response(fd, status, "application/json; charset=utf-8", body, length);
    free(body);
}

static int copy_header(char *target, size_t capacity, const char *value) {
    size_t length = strlen(value);
    if (length >= capacity) return 0;
    memcpy(target, value, length + 1);
    return 1;
}

static int parse_headers(char *data, Request *r) {
    char *line_end = strstr(data, "\r\n");
    if (!line_end) return 0;
    *line_end = 0;
    char version[16], extra;
    if (sscanf(data, "%15s %255s %15s %c", r->method, r->target, version, &extra) != 3 ||
        (strcmp(version, "HTTP/1.1") && strcmp(version, "HTTP/1.0")) || r->target[0] != '/') return 0;
    char *line = line_end + 2;
    int host_seen = 0, csrf_seen = 0, filename_seen = 0, content_type_seen = 0;
    for (unsigned int fields = 0; *line; fields++) {
        if (fields > 128) return 0;
        line_end = strstr(line, "\r\n");
        if (!line_end) return 0;
        *line_end = 0;
        if (!*line) break;
        char *colon = strchr(line, ':');
        if (!colon || colon == line) return 0;
        *colon = 0;
        for (char *p = line; *p; p++)
            if (!isalnum((unsigned char)*p) && *p != '-') return 0;
        char *value = colon + 1;
        while (*value == ' ' || *value == '\t') value++;
        char *end = value + strlen(value);
        while (end > value && (end[-1] == ' ' || end[-1] == '\t')) *--end = 0;
        for (char *p = value; *p; p++) if ((unsigned char)*p < 32 || (unsigned char)*p == 127) return 0;
        if (!strcasecmp(line, "Host")) {
            if (host_seen++ || !copy_header(r->host, sizeof r->host, value)) return 0;
        } else if (!strcasecmp(line, "Origin")) {
            if (r->has_origin++ || !copy_header(r->origin, sizeof r->origin, value)) return 0;
        } else if (!strcasecmp(line, "X-CSRF-Token")) {
            if (csrf_seen++ || !copy_header(r->csrf, sizeof r->csrf, value)) return 0;
        } else if (!strcasecmp(line, "X-Filename")) {
            if (filename_seen++ || !copy_header(r->filename, sizeof r->filename, value)) return 0;
        } else if (!strcasecmp(line, "Content-Type")) {
            if (content_type_seen++ || !copy_header(r->content_type, sizeof r->content_type, value)) return 0;
        } else if (!strcasecmp(line, "Transfer-Encoding")) return 0;
        else if (!strcasecmp(line, "Content-Length")) {
            if (r->has_length++ || !*value) return 0;
            for (char *p = value; *p; p++) if (*p < '0' || *p > '9') return 0;
            errno = 0;
            unsigned long long length = strtoull(value, NULL, 10);
            if (errno || length > MAX_BODY) return 413;
            r->length = (size_t)length;
        }
        line = line_end + 2;
    }
    return host_seen == 1 ? 1 : 0;
}

static int64_t monotonic_ms(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return 0;
    return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static ssize_t timed_recv(int fd, void *data, size_t capacity, int64_t deadline) {
    while (app_running) {
        int64_t remaining = deadline - monotonic_ms();
        if (remaining <= 0) return -1;
        struct pollfd wait = { fd, POLLIN, 0 };
        int ready = poll(&wait, 1, (int)remaining);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return -1;
        ssize_t got = recv(fd, data, capacity, 0);
        if (got < 0 && errno == EINTR) continue;
        return got;
    }
    return -1;
}

/* Complete the response before closing a rejected request with an unread body.
 * A direct close can issue TCP RST and discard the JSON error at the client. */
static void finish_client(int fd) {
    (void)shutdown(fd, SHUT_WR);
    int64_t deadline = monotonic_ms() + 200;
    size_t drained = 0;
    char pending[4096];
    while (app_running && drained < 65536) {
        int64_t remaining = deadline - monotonic_ms();
        if (remaining <= 0) break;
        struct pollfd ready = { fd, POLLIN, 0 };
        int status = poll(&ready, 1, (int)remaining);
        if (status < 0 && errno == EINTR) continue;
        if (status <= 0) break;
        ssize_t count = recv(fd, pending, sizeof pending, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        drained += (size_t)count;
    }
    close(fd);
}

static int read_request_parts(int fd, Request *r, unsigned short port, const char *token,
                               char buffer[MAX_HEADERS + 1], char headers[MAX_HEADERS + 1]) {
    size_t used = 0, header_size = 0;
    int64_t deadline = monotonic_ms() + 10000;
    while (used < MAX_HEADERS) {
        ssize_t got = timed_recv(fd, buffer + used, MAX_HEADERS - used, deadline);
        if (got <= 0) { json_error(fd, 408, "Richiesta incompleta o troppo lenta."); return 0; }
        used += (size_t)got;
        buffer[used] = 0;
        char *end = strstr(buffer, "\r\n\r\n");
        if (end) { header_size = (size_t)(end - buffer) + 4; break; }
    }
    if (!header_size) { json_error(fd, 431, "Intestazioni troppo grandi o non valide."); return 0; }
    if (memchr(buffer, 0, header_size)) { json_error(fd, 400, "Intestazioni non valide."); return 0; }
    memcpy(headers, buffer, header_size);
    headers[header_size] = 0;
    int parsed = parse_headers(headers, r);
    if (parsed != 1) { json_error(fd, parsed == 413 ? 413 : 400, "Richiesta HTTP non valida o troppo grande."); return 0; }
    char host_ip[64], host_name[64], origin[256];
    snprintf(host_ip, sizeof host_ip, "127.0.0.1:%u", port);
    snprintf(host_name, sizeof host_name, "localhost:%u", port);
    if (strcmp(r->host, host_ip) && strcmp(r->host, host_name) &&
        !(port == 80 && (!strcmp(r->host, "localhost") || !strcmp(r->host, "127.0.0.1")))) {
        json_error(fd, 403, "Accesso consentito solo dall'indirizzo locale del programma."); return 0;
    }
    snprintf(origin, sizeof origin, "http://%s", r->host);
    if (r->has_origin && strcmp(r->origin, origin)) {
        json_error(fd, 403, "Origine della richiesta non consentita."); return 0;
    }
    int mutating = strcmp(r->method, "GET") && strcmp(r->method, "HEAD");
    if (mutating && (strlen(r->csrf) != strlen(token) || CRYPTO_memcmp(r->csrf, token, strlen(token)))) {
        json_error(fd, 403, "Token di sicurezza mancante o scaduto: ricarica la pagina."); return 0;
    }
    if (r->length) {
        r->body = malloc(r->length);
        if (!r->body) { json_error(fd, 500, "Memoria insufficiente."); return 0; }
        size_t copied = used - header_size;
        if (copied > r->length) copied = r->length;
        memcpy(r->body, buffer + header_size, copied);
        while (copied < r->length) {
            ssize_t got = timed_recv(fd, r->body + copied, r->length - copied, deadline);
            if (got <= 0) { json_error(fd, 408, "Caricamento incompleto o troppo lento."); return 0; }
            copied += (size_t)got;
        }
    }
    return 1;
}

static int read_request(int fd, Request *r, unsigned short port, const char *token) {
    char buffer[MAX_HEADERS + 1], headers[MAX_HEADERS + 1];
    int ok = read_request_parts(fd, r, port, token, buffer, headers);
    /* The first receive can contain form credentials after the HTTP headers. */
    OPENSSL_cleanse(buffer, sizeof buffer);
    OPENSSL_cleanse(headers, sizeof headers);
    return ok;
}

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int filename_decode(const char *input, char output[256]) {
    size_t written = 0;
    if (!*input) input = "certificato.caricato";
    for (size_t i = 0; input[i]; i++) {
        unsigned char c = (unsigned char)input[i];
        if (c == '%') {
            if (!input[i + 1] || !input[i + 2]) return 0;
            int a = hex_digit(input[i + 1]), b = hex_digit(input[i + 2]);
            if (a < 0 || b < 0) return 0;
            c = (unsigned char)(a * 16 + b); i += 2;
        }
        if (c < 32 || c == 127 || c == '/' || c == '\\' || written >= 255) return 0;
        output[written++] = (char)c;
    }
    output[written] = 0;
    return written > 0;
}

static void upload(int fd, Store *store, const Request *r, int64_t renew_id) {
    if (!r->length) { json_error(fd, 400, "Seleziona un certificato PEM o DER non vuoto."); return; }
    char filename[256];
    if (!filename_decode(r->filename, filename)) {
        json_error(fd, 400, "Nome del file non valido o troppo lungo."); return;
    }
    char temporary[] = "/tmp/certificati-upload-XXXXXX";
    int temp_fd = mkstemp(temporary);
    if (temp_fd < 0) { json_error(fd, 500, "Impossibile creare il file temporaneo."); return; }
    size_t written = 0;
    int ok = 1;
    while (written < r->length) {
        ssize_t count = write(temp_fd, r->body + written, r->length - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ok = 0; break; }
        written += (size_t)count;
    }
    if (close(temp_fd)) ok = 0;
    char error[512] = "";
    int added = 0, duplicates = 0;
    int64_t new_id = 0;
    int queued = 0;
    if (ok) {
        if (renew_id) ok = app_renew(store, renew_id, temporary, filename, &new_id, &queued, error, sizeof error);
        else ok = app_import(store, temporary, filename, &added, &duplicates, error, sizeof error);
    }
    unlink(temporary);
    if (!ok) { json_error(fd, error[0] ? 400 : 500, error[0] ? error : "Errore di scrittura del file temporaneo."); return; }
    int count = 0;
    if (!app_check(store, (int64_t)time(NULL), &count, stdout, error, sizeof error))
        fprintf(stderr, "Controllo promemoria: %s\n", error);
    char body[256];
    int length = renew_id ? snprintf(body, sizeof body, "{\"ok\":true,\"certificate_id\":%" PRId64 ",\"queued\":%d}", new_id, queued) :
                           snprintf(body, sizeof body, "{\"ok\":true,\"imported\":%d,\"duplicates\":%d}", added, duplicates);
    response(fd, 200, "application/json; charset=utf-8", body, (size_t)length);
}

static int resource_path(const char *target, const char *prefix, int64_t *id, const char **action) {
    size_t length = strlen(prefix);
    if (strncmp(target, prefix, length)) return 0;
    const char *number = target + length;
    if (*number < '1' || *number > '9') return 0;
    errno = 0;
    char *end;
    long long parsed = strtoll(number, &end, 10);
    if (errno || parsed <= 0 || (*end && *end != '/')) return 0;
    *id = (int64_t)parsed;
    *action = end;
    return 1;
}

static char *form_decode(const unsigned char *data, size_t length) {
    char *result = malloc(length + 1);
    if (!result) return NULL;
    size_t written = 0;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = data[i];
        if (c == '%') {
            if (i + 2 >= length) goto invalid;
            int a = hex_digit((char)data[i + 1]), b = hex_digit((char)data[i + 2]);
            if (a < 0 || b < 0) goto invalid;
            c = (unsigned char)(a * 16 + b); i += 2;
        } else if (c == '+') c = ' ';
        if (c < 32 || c == 127) goto invalid;
        result[written++] = (char)c;
    }
    result[written] = 0;
    return result;
invalid:
    OPENSSL_cleanse(result, length + 1);
    free(result);
    return NULL;
}

static int single_form_value(const Request *r, const char *wanted, char **output,
                              int required, char *err, size_t n) {
    *output = NULL;
    if (r->length > 8192 || strncmp(r->content_type, "application/x-www-form-urlencoded", 33) ||
        (r->content_type[33] && r->content_type[33] != ';')) {
        snprintf(err, n, "Formato della richiesta non valido."); return 0;
    }
    for (size_t start = 0; start < r->length;) {
        size_t end = start;
        while (end < r->length && r->body[end] != '&') end++;
        size_t equal = start;
        while (equal < end && r->body[equal] != '=') equal++;
        if (equal == end) { snprintf(err, n, "Campo della richiesta non valido."); goto fail; }
        if (equal - start == strlen(wanted) && !memcmp(r->body + start, wanted, equal - start)) {
            if (*output) { snprintf(err, n, "Campo duplicato nella richiesta."); goto fail; }
            *output = form_decode(r->body + equal + 1, end - equal - 1);
            if (!*output) { snprintf(err, n, "Valore del campo non valido."); goto fail; }
        }
        start = end + 1;
    }
    if (required && (!*output || !**output)) { snprintf(err, n, "Indica URL o nome host del certificato da verificare."); goto fail; }
    return 1;
fail:
    if (*output) { OPENSSL_cleanse(*output, strlen(*output)); free(*output); }
    *output = NULL;
    return 0;
}

static void check_remote(int fd, Store *store, const Request *r) {
    char error[512] = "";
    char *target = NULL, *expected = NULL;
    int64_t expected_id = 0;
    if (!single_form_value(r, "target", &target, 1, error, sizeof error) ||
        !single_form_value(r, "certificate_id", &expected, 0, error, sizeof error)) goto invalid;
    if (expected && *expected) {
        errno = 0;
        char *end;
        long long id = strtoll(expected, &end, 10);
        if (errno || id <= 0 || *end) { snprintf(error, sizeof error, "Identificativo del certificato non valido."); goto invalid; }
        for (const char *p = expected; *p; p++)
            if (*p < '0' || *p > '9') { snprintf(error, sizeof error, "Identificativo del certificato non valido."); goto invalid; }
        expected_id = (int64_t)id;
    }
    size_t length = 0;
    int status = 400;
    char *body = remote_check_json(store, target, expected_id, &length, &status, error, sizeof error);
    free(target); free(expected);
    if (!body) json_error(fd, status, error);
    else { response(fd, status, "application/json; charset=utf-8", body, length); free(body); }
    return;
invalid:
    free(target); free(expected);
    json_error(fd, 400, error);
}

static void import_remote(int fd, Store *store, const Request *r) {
    char error[512] = "", *token = NULL;
    if (!single_form_value(r, "token", &token, 1, error, sizeof error)) { json_error(fd, 400, error); return; }
    int imported = 0, duplicates = 0;
    int64_t id = 0;
    const char *snapshot_target = remote_snapshot_target(token);
    char *target = snapshot_target ? strdup(snapshot_target) : NULL;
    if (snapshot_target && !target) { free(token); json_error(fd, 500, "Memoria insufficiente."); return; }
    int ok = remote_import_snapshot(store, token, &imported, &duplicates, &id, error, sizeof error);
    free(token);
    if (!ok) { free(target); json_error(fd, 400, error); return; }
    int64_t monitor_id = 0;
    int monitoring_added = 0;
    char monitoring_error[512] = "";
    sqlite3_stmt *existing = NULL;
    if (target) {
        ok = sqlite3_prepare_v2(store->db, "SELECT m.id,c.is_ca,c.archived FROM certificates c "
                                 "LEFT JOIN monitors m ON m.certificate_id=c.id AND m.target=?2 WHERE c.id=?1",
                                 -1, &existing, NULL) == SQLITE_OK &&
             sqlite3_bind_int64(existing, 1, id) == SQLITE_OK &&
             sqlite3_bind_text(existing, 2, target, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
             sqlite3_step(existing) == SQLITE_ROW;
        if (ok) {
            monitor_id = sqlite3_column_int64(existing, 0);
            int eligible = !sqlite3_column_int(existing, 1) && !sqlite3_column_int(existing, 2);
            sqlite3_finalize(existing); existing = NULL;
            if (!monitor_id && eligible)
                monitoring_added = monitor_save(store, 0, id, target, 900, 1, (int64_t)time(NULL),
                                                &monitor_id, monitoring_error, sizeof monitoring_error);
        } else snprintf(monitoring_error, sizeof monitoring_error, "%s", sqlite3_errmsg(store->db));
        sqlite3_finalize(existing);
    }
    free(target);
    int count = 0;
    if (!app_check(store, (int64_t)time(NULL), &count, stdout, error, sizeof error))
        fprintf(stderr, "Controllo dopo acquisizione online: %s\n", error);
    char *body = NULL;
    size_t length = 0;
    FILE *out = open_memstream(&body, &length);
    if (!out) { json_error(fd, 500, "Importazione completata; impossibile generare la risposta."); return; }
    fprintf(out, "{\"ok\":true,\"imported\":%d,\"duplicates\":%d,\"certificate_id\":%" PRId64
                 ",\"monitor_id\":%" PRId64 ",\"monitoring_added\":%s,\"monitoring_error\":",
            imported, duplicates, id, monitor_id, monitoring_added ? "true" : "false");
    app_json_string(out, monitoring_error);
    fputc('}', out);
    int failed = ferror(out);
    if (fclose(out)) failed = 1;
    if (failed) json_error(fd, 500, "Importazione completata; impossibile generare la risposta.");
    else response(fd, 200, "application/json; charset=utf-8", body, length);
    free(body);
}

static int form_number(const char *value, int64_t minimum, int64_t maximum, int64_t *parsed) {
    if (!value || !*value) return 0;
    for (const char *p = value; *p; p++) if (*p < '0' || *p > '9') return 0;
    errno = 0;
    char *end;
    long long number = strtoll(value, &end, 10);
    if (errno || *end || number < minimum || number > maximum) return 0;
    *parsed = (int64_t)number;
    return 1;
}

static void save_monitor(int fd, Store *store, const Request *r, int64_t id) {
    char error[512] = "";
    char *cert = NULL, *target = NULL, *interval = NULL, *enabled = NULL;
    int64_t certificate_id = 0, minutes = 15, active = 1, saved_id = 0;
    int ok = single_form_value(r, "certificate_id", &cert, 1, error, sizeof error) &&
             single_form_value(r, "target", &target, 1, error, sizeof error) &&
             single_form_value(r, "interval_minutes", &interval, 0, error, sizeof error) &&
             single_form_value(r, "enabled", &enabled, 0, error, sizeof error);
    if (ok && (!form_number(cert, 1, INT64_MAX, &certificate_id) ||
               (interval && !form_number(interval, 1, 1440, &minutes)) ||
               (enabled && !form_number(enabled, 0, 1, &active)))) {
        snprintf(error, sizeof error, "Certificato, intervallo (1–1440 minuti) o stato del monitoraggio non valido."); ok = 0;
    }
    if (ok) ok = monitor_save(store, id, certificate_id, target, (int)(minutes * 60), (int)active,
                              (int64_t)time(NULL), &saved_id, error, sizeof error);
    free(cert); free(target); free(interval); free(enabled);
    if (!ok) { json_error(fd, 400, error); return; }
    char body[96];
    int length = snprintf(body, sizeof body, "{\"ok\":true,\"monitor_id\":%" PRId64 "}", saved_id);
    response(fd, 200, "application/json; charset=utf-8", body, (size_t)length);
}

static void acknowledge_monitor_event(int fd, Store *store, int64_t id) {
    sqlite3_stmt *stmt = NULL;
    int ok = sqlite3_prepare_v2(store->db, "UPDATE monitor_events SET acknowledged_at=coalesce(acknowledged_at,?2) WHERE id=?1",
                               -1, &stmt, NULL) == SQLITE_OK &&
             sqlite3_bind_int64(stmt, 1, id) == SQLITE_OK &&
             sqlite3_bind_int64(stmt, 2, (int64_t)time(NULL)) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_DONE;
    int changed = ok ? sqlite3_changes(store->db) : 0;
    sqlite3_finalize(stmt);
    if (!ok) json_error(fd, 500, "Impossibile aggiornare la segnalazione.");
    else if (!changed) json_error(fd, 404, "Segnalazione non trovata.");
    else {
        const char body[] = "{\"ok\":true}";
        response(fd, 200, "application/json; charset=utf-8", body, sizeof body - 1);
    }
}

static const char *remote_download_token(const char *target, char token[33]) {
    const char prefix[] = "/api/remote/";
    if (strlen(target) != sizeof prefix - 1 + 32 + strlen("/download") ||
        strncmp(target, prefix, sizeof prefix - 1)) return NULL;
    const char *start = target + sizeof prefix - 1;
    for (size_t i = 0; i < 32; i++) if (!isxdigit((unsigned char)start[i])) return NULL;
    if (strcmp(start + 32, "/download")) return NULL;
    memcpy(token, start, 32); token[32] = 0;
    return token;
}

static void update_contacts(int fd, Store *store, int64_t id, const Request *r) {
    if (r->length > 65536 || strncmp(r->content_type, "application/x-www-form-urlencoded", 33) ||
        (r->content_type[33] && r->content_type[33] != ';')) {
        json_error(fd, 400, "Formato referenti non valido o troppo grande."); return;
    }
    char *values[3][100] = {{0}};
    size_t counts[3] = {0};
    int valid = 1;
    for (size_t start = 0; start < r->length && valid;) {
        size_t end = start;
        while (end < r->length && r->body[end] != '&') end++;
        size_t equal = start;
        while (equal < end && r->body[equal] != '=') equal++;
        int kind = -1;
        if (equal - start == 4 && !memcmp(r->body + start, "role", 4)) kind = 0;
        if (equal - start == 4 && !memcmp(r->body + start, "name", 4)) kind = 1;
        if (equal - start == 5 && !memcmp(r->body + start, "email", 5)) kind = 2;
        if (kind < 0 || equal == end || counts[kind] >= 100) valid = 0;
        else {
            char *value = form_decode(r->body + equal + 1, end - equal - 1);
            if (!value) valid = 0;
            else values[kind][counts[kind]++] = value;
        }
        start = end + 1;
    }
    if (counts[0] != counts[1] || counts[0] != counts[2]) valid = 0;
    char error[512] = "";
    int ok = 0;
    StoreContact contacts[100];
    if (valid) {
        for (size_t i = 0; i < counts[0]; i++) {
            contacts[i].role = values[0][i];
            contacts[i].name = values[1][i];
            contacts[i].email = values[2][i];
        }
        if (store_exec(store, "BEGIN IMMEDIATE", error, sizeof error)) {
            ok = store_set_contacts(store, id, contacts, counts[0], error, sizeof error);
            sqlite3_stmt *prune = NULL;
            if (ok) {
                ok = sqlite3_prepare_v2(store->db, "DELETE FROM outbox WHERE certificate_id=?1 "
                       "AND status IN('pending','failed') AND NOT EXISTS (SELECT 1 FROM contacts c "
                       "WHERE c.certificate_id=outbox.certificate_id AND c.email=outbox.recipient_email COLLATE NOCASE "
                       "AND c.role=CASE outbox.kind WHEN 'expiry' THEN 'business' ELSE 'technical' END)",
                       -1, &prune, NULL) == SQLITE_OK &&
                     sqlite3_bind_int64(prune, 1, id) == SQLITE_OK && sqlite3_step(prune) == SQLITE_DONE;
                if (!ok) snprintf(error, sizeof error, "Errore aggiornamento coda: %s", sqlite3_errmsg(store->db));
            }
            sqlite3_finalize(prune);
            if (ok) ok = store_exec(store, "COMMIT", error, sizeof error);
            if (!ok) sqlite3_exec(store->db, "ROLLBACK", NULL, NULL, NULL);
        }
    }
    for (size_t k = 0; k < 3; k++) for (size_t i = 0; i < counts[k]; i++) free(values[k][i]);
    if (!ok) { json_error(fd, 400, error[0] ? error : "Elenco referenti non valido."); return; }
    int count = 0;
    if (!app_check(store, (int64_t)time(NULL), &count, stdout, error, sizeof error))
        fprintf(stderr, "Controllo dopo modifica referenti: %s\n", error);
    const char body[] = "{\"ok\":true}";
    response(fd, 200, "application/json; charset=utf-8", body, sizeof body - 1);
}

static void process_delivery(int fd, Store *store) {
    char error[512] = "";
    int sent = 0;
    if (!delivery_process(store, (int64_t)time(NULL), &sent, error, sizeof error)) {
        json_error(fd, 500, error); return;
    }
    char body[160];
    int length = snprintf(body, sizeof body, "{\"ok\":true,\"sent\":%d,\"configured\":%s}",
                          sent, delivery_is_configured(store) ? "true" : "false");
    response(fd, 200, "application/json; charset=utf-8", body, (size_t)length);
}

static void configure_smtp(int fd, Store *store, const Request *r, int test_only) {
    static const char *const names[] = { "enabled", "host", "port", "security", "from_email",
                                         "username", "password", "clear_password" };
    char *values[sizeof names / sizeof names[0]] = {0};
    char error[512] = "";
    SmtpSettings resolved = {0};
    int64_t enabled = 0, port = 0, clear_password = 0;
    int status = 400, ok = 1;
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        if (!single_form_value(r, names[i], &values[i], 0, error, sizeof error)) { ok = 0; break; }
    }
    if (ok && (!form_number(values[0], 0, 1, &enabled) ||
               !form_number(values[2], 1, 65535, &port) ||
               (values[7] && !form_number(values[7], 0, 1, &clear_password)))) {
        snprintf(error, sizeof error, "Indica uno stato valido e una porta SMTP da 1 a 65535."); ok = 0;
    }
    if (ok) {
        SmtpSettings input = { .exists = 1, .enabled = (int)enabled, .port = (int)port,
            .host = values[1] ? values[1] : "", .security = values[3] ? values[3] : "",
            .from_email = values[4] ? values[4] : "", .username = values[5] ? values[5] : "",
            .password = values[6] ? values[6] : "", .source = "database" };
        ok = smtp_settings_prepare(store, &input, (int)clear_password, &resolved, error, sizeof error);
    }
    if (ok && test_only) {
        ok = smtp_settings_validate(&resolved, 1, error, sizeof error);
        if (ok) {
            status = 502;
            ok = delivery_test_connection(&resolved, error, sizeof error);
        }
    } else if (ok) {
        status = 500;
        ok = smtp_settings_save(store, &resolved, (int64_t)time(NULL), error, sizeof error);
    }
    int active = resolved.enabled;
    smtp_settings_free(&resolved);
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        if (values[i]) { OPENSSL_cleanse(values[i], strlen(values[i])); free(values[i]); }
    }
    if (!ok) { json_error(fd, status, error); return; }
    const char *body = test_only ?
        "{\"ok\":true,\"message\":\"Collegamento SMTP sicuro e autenticazione, se configurata, verificati. Nessuna email inviata; configurazione non salvata.\"}" : active ?
        "{\"ok\":true,\"message\":\"Configurazione SMTP salvata. Invio automatico abilitato.\"}" :
        "{\"ok\":true,\"message\":\"Configurazione SMTP salvata. Invio automatico in pausa.\"}";
    response(fd, 200, "application/json; charset=utf-8", body, strlen(body));
}

static int serve_ui_page(int fd, const char *target) {
    struct Page {
        const char *path;
        const unsigned char *body;
        size_t length;
    };
    const struct Page pages[] = {
        { "/", asset_index_html, asset_index_html_size },
        { "/certificati", asset_registry_html, asset_registry_html_size },
        { "/servizi", asset_monitoring_html, asset_monitoring_html_size },
        { "/importa", asset_import_html, asset_import_html_size },
        { "/verifica", asset_verify_html, asset_verify_html_size },
        { "/promemoria", asset_reminders_html, asset_reminders_html_size },
        { "/email", asset_delivery_html, asset_delivery_html_size }
    };
    size_t length = strcspn(target, "?");
    if (length > 1 && target[length - 1] == '/' && target[length - 2] != '/') length--;
    for (size_t i = 0; i < sizeof pages / sizeof pages[0]; i++) {
        if (strlen(pages[i].path) == length && !memcmp(target, pages[i].path, length)) {
            response(fd, 200, "text/html; charset=utf-8", pages[i].body, pages[i].length);
            return 1;
        }
    }
    return 0;
}

static void route(int fd, Store *store, const Request *r, const char *token) {
    int64_t certificate_id = 0, outbox_id = 0, monitor_id = 0, event_id = 0;
    const char *certificate_action = "", *outbox_action = "", *monitor_action = "", *event_action = "";
    int cert_path = resource_path(r->target, "/api/certificates/", &certificate_id, &certificate_action);
    int out_path = resource_path(r->target, "/api/outbox/", &outbox_id, &outbox_action);
    int monitor_path = resource_path(r->target, "/api/monitors/", &monitor_id, &monitor_action);
    int event_path = resource_path(r->target, "/api/monitor-events/", &event_id, &event_action);
    char remote_token[33];
    const char *download_token = remote_download_token(r->target, remote_token);
    if (!strcmp(r->method, "GET")) {
        if (serve_ui_page(fd, r->target)) { /* Each route has its own HTML document. */ }
        else if (!strcmp(r->target, "/app.css"))
            response(fd, 200, "text/css; charset=utf-8", asset_app_css, asset_app_css_size);
        else if (!strcmp(r->target, "/app.js"))
            response(fd, 200, "text/javascript; charset=utf-8", asset_app_js, asset_app_js_size);
        else if (!strcmp(r->target, "/i18n.js"))
            response(fd, 200, "text/javascript; charset=utf-8", asset_i18n_js, asset_i18n_js_size);
        else if (!strcmp(r->target, "/i18n-catalogs.js"))
            response(fd, 200, "text/javascript; charset=utf-8", asset_i18n_catalogs_js, asset_i18n_catalogs_js_size);
        else if (!strcmp(r->target, "/api/state")) {
            char error[512] = "";
            size_t length = 0;
            char *body = app_state_json(store, token, &length, error, sizeof error);
            if (body) { response(fd, 200, "application/json; charset=utf-8", body, length); free(body); }
            else json_error(fd, 500, error);
        } else if (download_token) {
            size_t length = 0;
            const char *pem = remote_snapshot_pem(download_token, &length);
            if (!pem) json_error(fd, 404, "Certificato temporaneo scaduto o non trovato: ripeti la verifica online.");
            else response_extended(fd, 200, "application/x-pem-file", pem, length, "certificato-online.pem");
        } else if (cert_path && !strcmp(certificate_action, "/download")) {
            char error[512] = "", filename[80];
            CertificateChain chain = {0};
            if (!chain_describe(store, certificate_id, &chain, error, sizeof error)) json_error(fd, 404, error);
            else if (!chain.pem_bundle || !*chain.pem_bundle) json_error(fd, 400, "Ricarica il certificato originale per scaricarlo.");
            else {
                snprintf(filename, sizeof filename, "certificate-%" PRId64 ".pem", certificate_id);
                response_extended(fd, 200, "application/x-pem-file", chain.pem_bundle, strlen(chain.pem_bundle), filename);
            }
            chain_free(&chain);
        } else if (out_path && !strcmp(outbox_action, "/message")) {
            char error[512] = "", filename[80];
            size_t length = 0;
            char *message = delivery_message(store, outbox_id, &length, error, sizeof error);
            if (!message) json_error(fd, 404, error);
            else {
                snprintf(filename, sizeof filename, "messaggio-%" PRId64 ".eml", outbox_id);
                response_extended(fd, 200, "message/rfc822", message, length, filename);
                free(message);
            }
        } else json_error(fd, 404, "Risorsa non trovata.");
    } else if (!strcmp(r->method, "PUT") && !strcmp(r->target, "/api/smtp/settings")) {
        configure_smtp(fd, store, r, 0);
    } else if (!strcmp(r->method, "POST") && !strcmp(r->target, "/api/smtp/test")) {
        configure_smtp(fd, store, r, 1);
    } else if ((!strcmp(r->method, "POST") && !strcmp(r->target, "/api/monitors")) ||
               (!strcmp(r->method, "PUT") && monitor_path && !*monitor_action)) {
        save_monitor(fd, store, r, monitor_path ? monitor_id : 0);
    } else if ((!strcmp(r->method, "POST") && monitor_path && !strcmp(monitor_action, "/check")) ||
               (!strcmp(r->method, "DELETE") && monitor_path && !*monitor_action)) {
        char error[512] = "";
        int ok = !strcmp(r->method, "DELETE") ? monitor_remove(store, monitor_id, error, sizeof error) :
                 monitor_request(store, monitor_id, (int64_t)time(NULL), error, sizeof error);
        if (!ok) json_error(fd, 400, error);
        else {
            const char body[] = "{\"ok\":true}";
            response(fd, 200, "application/json; charset=utf-8", body, sizeof body - 1);
        }
    } else if (!strcmp(r->method, "POST") && event_path && !strcmp(event_action, "/ack")) {
        acknowledge_monitor_event(fd, store, event_id);
    } else if (!strcmp(r->method, "POST") && !strcmp(r->target, "/api/remote/check")) {
        check_remote(fd, store, r);
    } else if (!strcmp(r->method, "POST") && !strcmp(r->target, "/api/remote/import")) {
        import_remote(fd, store, r);
    } else if (!strcmp(r->method, "POST") && !strcmp(r->target, "/api/certificates")) {
        upload(fd, store, r, 0);
    } else if (!strcmp(r->method, "PUT") && cert_path && !strcmp(certificate_action, "/contacts")) {
        update_contacts(fd, store, certificate_id, r);
    } else if (!strcmp(r->method, "POST") && cert_path && !strcmp(certificate_action, "/renew")) {
        upload(fd, store, r, certificate_id);
    } else if (!strcmp(r->method, "POST") && cert_path && !strcmp(certificate_action, "/distribute")) {
        char error[512] = "";
        int queued = 0;
        if (!app_distribute(store, certificate_id, &queued, error, sizeof error)) json_error(fd, 400, error);
        else {
            char body[128];
            int length = snprintf(body, sizeof body, "{\"ok\":true,\"queued\":%d}", queued);
            response(fd, 200, "application/json; charset=utf-8", body, (size_t)length);
        }
    } else if (!strcmp(r->method, "POST") && !strcmp(r->target, "/api/delivery/process")) {
        process_delivery(fd, store);
    } else if (!strcmp(r->method, "POST") && out_path && !strcmp(outbox_action, "/retry")) {
        sqlite3_stmt *stmt = NULL;
        int ok = sqlite3_prepare_v2(store->db, "UPDATE outbox SET status='pending',attempts=0,last_error='',next_attempt=0 "
                                    "WHERE id=?1 AND status='failed'", -1, &stmt, NULL) == SQLITE_OK &&
                 sqlite3_bind_int64(stmt, 1, outbox_id) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_DONE;
        int changed = ok ? sqlite3_changes(store->db) : 0;
        sqlite3_finalize(stmt);
        if (!ok) json_error(fd, 500, "Impossibile riprogrammare l'invio.");
        else if (!changed) json_error(fd, 400, "Messaggio fallito non trovato o già riprogrammato.");
        else {
            const char body[] = "{\"ok\":true}";
            response(fd, 200, "application/json; charset=utf-8", body, sizeof body - 1);
        }
    } else if (!strcmp(r->method, "POST") && !strcmp(r->target, "/api/check")) {
        char error[512] = "";
        int count = 0;
        if (!app_check(store, (int64_t)time(NULL), &count, stdout, error, sizeof error)) json_error(fd, 500, error);
        else {
            char body[128];
            int length = snprintf(body, sizeof body, "{\"ok\":true,\"new_notifications\":%d}", count);
            response(fd, 200, "application/json; charset=utf-8", body, (size_t)length);
        }
    } else if (!strcmp(r->method, "DELETE") && cert_path && !*certificate_action) {
        char error[512] = "";
        int removed;
        if (!store_remove(store, certificate_id, &removed, error, sizeof error)) json_error(fd, 500, error);
        else if (!removed) json_error(fd, 404, "Certificato non trovato.");
        else {
            const char body[] = "{\"ok\":true}";
            response(fd, 200, "application/json; charset=utf-8", body, sizeof body - 1);
        }
    } else json_error(fd, 405, "Metodo o percorso non supportato.");
}

int app_serve(Store *store, unsigned short port) {
    unsigned char random[32];
    char token[65];
    if (RAND_bytes(random, sizeof random) != 1) {
        fprintf(stderr, "Impossibile generare il token di sicurezza.\n"); return 0;
    }
    for (size_t i = 0; i < sizeof random; i++) snprintf(token + i * 2, 3, "%02x", random[i]);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 0; }
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    (void)inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    address.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&address, sizeof address) || listen(fd, 16)) {
        fprintf(stderr, "Impossibile avviare http://127.0.0.1:%u: %s\n", port, strerror(errno));
        close(fd); return 0;
    }
    printf("Gestione certificati: http://127.0.0.1:%u\n"
           "Controllo scadenze ogni 60 secondi; monitoraggio URL in background. Premi Ctrl+C per terminare.\n", port);
    fflush(stdout);
    int64_t next_check = 0;
    int success = 1;
    while (app_running) {
        char monitor_error[512] = "";
        if (!monitor_tick(store, (int64_t)time(NULL), monitor_error, sizeof monitor_error))
            fprintf(stderr, "Monitoraggio URL: %s\n", monitor_error);
        int64_t tick = monotonic_ms();
        if (tick >= next_check) {
            char error[512] = "";
            int count;
            if (!app_check(store, (int64_t)time(NULL), &count, stdout, error, sizeof error))
                fprintf(stderr, "Controllo promemoria: %s\n", error);
            int sent = 0;
            if (!delivery_process(store, (int64_t)time(NULL), &sent, error, sizeof error))
                fprintf(stderr, "Invio email: %s\n", error);
            next_check = tick + 60000;
        }
        struct pollfd wait = { fd, POLLIN, 0 };
        int ready = poll(&wait, 1, 1000);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) { perror("poll"); success = 0; break; }
        if (!ready) continue;
        int client = accept(fd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            perror("accept"); success = 0; break;
        }
        struct timeval timeout = { 5, 0 };
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
        Request request = {0};
        if (read_request(client, &request, port, token)) route(client, store, &request, token);
        if (request.body) { OPENSSL_cleanse(request.body, request.length); free(request.body); }
        finish_client(client);
    }
    close(fd);
    monitor_shutdown();
    remote_cache_clear();
    return success;
}
