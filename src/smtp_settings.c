#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include "smtp_settings.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PASSWORD_MAX 4096
#define NONCE_SIZE 12
#define TAG_SIZE 16
#define CIPHER_HEADER (1 + NONCE_SIZE + TAG_SIZE)

static const unsigned char cipher_aad[] = "certificati.smtp.v1";

static int fail(char *err, size_t n, const char *format, ...)
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
    return fail(err, n, "Errore configurazione SMTP: %s", sqlite3_errmsg(store->db));
}

static const char *value(const char *text)
{
    return text != NULL ? text : "";
}

static int present(const char *text)
{
    return text != NULL && text[0] != '\0';
}

static void secret_free(char *text)
{
    if (text != NULL) {
        OPENSSL_cleanse(text, strlen(text));
        free(text);
    }
}

void smtp_settings_free(SmtpSettings *settings)
{
    if (settings == NULL) return;
    free(settings->host);
    free(settings->security);
    free(settings->from_email);
    free(settings->username);
    secret_free(settings->password);
    memset(settings, 0, sizeof *settings);
}

static int basic_settings(SmtpSettings *out, char *err, size_t n)
{
    memset(out, 0, sizeof *out);
    out->port = 587;
    out->source = "none";
    out->host = strdup("");
    out->security = strdup("starttls");
    out->from_email = strdup("");
    out->username = strdup("");
    if (!out->host || !out->security || !out->from_email || !out->username) {
        smtp_settings_free(out);
        return fail(err, n, "Memoria insufficiente per la configurazione SMTP.");
    }
    return 1;
}

static int safe_text(const char *text, size_t maximum)
{
    if (text == NULL || strlen(text) > maximum) return 0;
    const unsigned char *p = (const unsigned char *)text;
    while (*p != '\0') {
        unsigned char first = *p++;
        if (first < 32 || first == 127) return 0;
        if (first < 128) continue;
        int count;
        unsigned int scalar;
        if (first >= 0xc2 && first <= 0xdf) { count = 1; scalar = first & 0x1f; }
        else if (first >= 0xe0 && first <= 0xef) { count = 2; scalar = first & 0x0f; }
        else if (first >= 0xf0 && first <= 0xf4) { count = 3; scalar = first & 0x07; }
        else return 0;
        for (int i = 0; i < count; ++i) {
            if ((*p & 0xc0) != 0x80) return 0;
            scalar = (scalar << 6) | (*p++ & 0x3f);
        }
        if ((count == 2 && scalar < 0x800) || (count == 3 && scalar < 0x10000) ||
            scalar > 0x10ffff || (scalar >= 0xd800 && scalar <= 0xdfff)) return 0;
    }
    return 1;
}

static int valid_mailbox(const char *email)
{
    if (!email || strlen(email) > 254) return 0;
    const char *at = strchr(email, '@');
    if (!at || at == email || at - email > 64 || strchr(at + 1, '@') ||
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

static char *canonical_host(const char *host)
{
    if (!host) return strdup("");
    size_t length = strlen(host);
    if (length >= 2 && host[0] == '[' && host[length - 1] == ']') {
        ++host;
        length -= 2;
    }
    char *copy = strndup(host, length);
    if (copy != NULL) {
        for (char *p = copy; *p; ++p) *p = (char)tolower((unsigned char)*p);
    }
    return copy;
}

static int valid_host(const char *host)
{
    if (!host || !*host || strlen(host) > 253) return 0;
    unsigned char address[16];
    if (strchr(host, ':')) return inet_pton(AF_INET6, host, address) == 1;
    const char *label = host;
    for (const char *p = host;; ++p) {
        unsigned char c = (unsigned char)*p;
        if (!c || c == '.') {
            if (p == label || p - label > 63 || label[0] == '-' || p[-1] == '-') return 0;
            if (!c || !p[1]) break;
            label = p + 1;
        } else if (!(c < 128 && (isalnum(c) || c == '-'))) return 0;
    }
    return 1;
}

int smtp_settings_validate(const SmtpSettings *settings, int require_complete,
                           char *err, size_t n)
{
    if (err && n) err[0] = '\0';
    if (!settings) return fail(err, n, "Configurazione SMTP mancante.");
    if (settings->enabled != 0 && settings->enabled != 1)
        return fail(err, n, "Stato SMTP non valido.");
    if (settings->port < 1 || settings->port > 65535)
        return fail(err, n, "La porta SMTP deve essere compresa tra 1 e 65535.");
    if (strcmp(value(settings->security), "starttls") && strcmp(value(settings->security), "tls"))
        return fail(err, n, "Selezionare STARTTLS oppure TLS implicito.");
    if (present(settings->host) && !valid_host(settings->host))
        return fail(err, n, "Server SMTP non valido: inserire solo il nome host o l'indirizzo IP, senza URL.");
    if (present(settings->from_email) && !valid_mailbox(settings->from_email))
        return fail(err, n, "Indirizzo email del mittente non valido.");
    if (!safe_text(value(settings->username), 1024))
        return fail(err, n, "Nome utente SMTP non valido.");
    if (settings->password && !safe_text(settings->password, PASSWORD_MAX))
        return fail(err, n, "Password SMTP non valida o troppo lunga.");
    int has_password = present(settings->password) || settings->password_set;
    if (!!present(settings->username) != !!has_password)
        return fail(err, n, "Indicare sia il nome utente sia la password, oppure lasciare entrambi vuoti.");
    if ((require_complete || settings->enabled) &&
        (!present(settings->host) || !present(settings->from_email)))
        return fail(err, n, "Per usare SMTP sono necessari server e indirizzo mittente.");
    return 1;
}

static char *column_text(sqlite3_stmt *stmt, int column)
{
    const unsigned char *text = sqlite3_column_text(stmt, column);
    int length = sqlite3_column_bytes(stmt, column);
    if (!text || length < 0 || memchr(text, 0, (size_t)length)) return NULL;
    return strndup((const char *)text, (size_t)length);
}

static int read_key(int fd, unsigned char key[32], char *err, size_t n)
{
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 077) != 0 || st.st_size != 32)
        return fail(err, n, "File della chiave SMTP non sicuro o non valido: richiesti proprietario corrente, permessi 0600 e 32 byte.");
    size_t used = 0;
    while (used < 32) {
        ssize_t count = read(fd, key + used, 32 - used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return fail(err, n, "Impossibile leggere la chiave SMTP.");
        used += (size_t)count;
    }
    return 1;
}

static int encryption_key(Store *store, int allow_create, char *err, size_t n)
{
    const char *database = sqlite3_db_filename(store->db, "main");
    if (!database || !database[0]) {
        if (store->smtp_key_loaded) return 1;
        if (!allow_create) return fail(err, n, "Chiave SMTP temporanea mancante.");
        if (RAND_bytes(store->smtp_key, sizeof store->smtp_key) != 1)
            return fail(err, n, "Impossibile generare la chiave SMTP.");
        store->smtp_key_loaded = 1;
        return 1;
    }
    size_t length = strlen(database);
    if (length > SIZE_MAX - sizeof ".smtp.key")
        return fail(err, n, "Percorso della chiave SMTP troppo lungo.");
    char *path = malloc(length + sizeof ".smtp.key");
    if (!path) return fail(err, n, "Memoria insufficiente per la chiave SMTP.");
    (void)snprintf(path, length + sizeof ".smtp.key", "%s.smtp.key", database);
    OPENSSL_cleanse(store->smtp_key, sizeof store->smtp_key);
    store->smtp_key_loaded = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0) {
        int ok = read_key(fd, store->smtp_key, err, n);
        if (close(fd) < 0 && ok) ok = fail(err, n, "Impossibile chiudere il file della chiave SMTP.");
        free(path);
        if (ok) store->smtp_key_loaded = 1;
        else OPENSSL_cleanse(store->smtp_key, sizeof store->smtp_key);
        return ok;
    }
    if (errno != ENOENT || !allow_create) {
        free(path);
        return fail(err, n, "Chiave SMTP mancante o non accessibile; ripristinare il file .smtp.key originale.");
    }
    unsigned char generated[32];
    if (RAND_bytes(generated, sizeof generated) != 1) {
        free(path);
        return fail(err, n, "Impossibile generare la chiave SMTP.");
    }
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        int race = errno == EEXIST;
        OPENSSL_cleanse(generated, sizeof generated);
        free(path);
        if (race) return encryption_key(store, allow_create, err, n);
        return fail(err, n, "Impossibile creare il file della chiave SMTP.");
    }
    size_t used = 0;
    int ok = 1;
    while (used < sizeof generated) {
        ssize_t count = write(fd, generated + used, sizeof generated - used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { ok = 0; break; }
        used += (size_t)count;
    }
    if (ok && fsync(fd) < 0) ok = 0;
    if (close(fd) < 0) ok = 0;
    if (!ok) {
        (void)unlink(path);
        OPENSSL_cleanse(generated, sizeof generated);
        free(path);
        return fail(err, n, "Impossibile salvare in modo sicuro la chiave SMTP.");
    }
    memcpy(store->smtp_key, generated, sizeof generated);
    store->smtp_key_loaded = 1;
    OPENSSL_cleanse(generated, sizeof generated);
    free(path);
    return 1;
}

static int decrypt_password(Store *store, const unsigned char *blob, int length,
                             char **password, char *err, size_t n)
{
    *password = NULL;
    if (length <= CIPHER_HEADER || length > CIPHER_HEADER + PASSWORD_MAX || !blob || blob[0] != 1)
        return fail(err, n, "Password SMTP cifrata non valida.");
    if (!encryption_key(store, 0, err, n)) return 0;
    int plain_size = length - CIPHER_HEADER;
    char *plain = calloc((size_t)plain_size + 1, 1);
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (!plain || !context) {
        free(plain);
        EVP_CIPHER_CTX_free(context);
        return fail(err, n, "Memoria insufficiente per la password SMTP.");
    }
    int output = 0, tail = 0;
    int ok = EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL) == 1 &&
        EVP_DecryptInit_ex(context, NULL, NULL, store->smtp_key, blob + 1) == 1 &&
        EVP_DecryptUpdate(context, NULL, &output, cipher_aad, sizeof cipher_aad - 1) == 1 &&
        EVP_DecryptUpdate(context, (unsigned char *)plain, &output, blob + CIPHER_HEADER, plain_size) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void *)(blob + 1 + NONCE_SIZE)) == 1 &&
        EVP_DecryptFinal_ex(context, (unsigned char *)plain + output, &tail) == 1;
    EVP_CIPHER_CTX_free(context);
    if (!ok || output + tail != plain_size || memchr(plain, 0, (size_t)plain_size)) {
        OPENSSL_cleanse(plain, (size_t)plain_size + 1);
        free(plain);
        return fail(err, n, "Impossibile decifrare la password SMTP: chiave errata o dati danneggiati.");
    }
    *password = plain;
    return 1;
}

static const char *environment(const char *name)
{
    const char *text = getenv(name);
    return present(text) ? text : NULL;
}

static int load_environment(SmtpSettings *out, int with_secret, char *err, size_t n)
{
    const char *url_text = environment("CERTIFICATI_SMTP_URL");
    const char *from = environment("CERTIFICATI_SMTP_FROM");
    const char *username = environment("CERTIFICATI_SMTP_USERNAME");
    const char *password = environment("CERTIFICATI_SMTP_PASSWORD");
    if (!url_text && !from && !username && !password) return 1;
    out->source = "environment";
    out->enabled = 1;
    out->password_set = password != NULL;
    free(out->from_email); out->from_email = strdup(value(from));
    free(out->username); out->username = strdup(value(username));
    if (with_secret && password) out->password = strdup(password);
    if (!out->from_email || !out->username || (with_secret && password && !out->password))
        return fail(err, n, "Memoria insufficiente per la configurazione SMTP.");
    if (!url_text) return 1;
    CURLU *url = curl_url();
    if (!url) return fail(err, n, "Memoria insufficiente per la configurazione SMTP.");
    char *scheme = NULL, *host = NULL, *port = NULL, *path = NULL, *query = NULL, *fragment = NULL;
    int valid = safe_text(url_text, 4096) &&
        curl_url_set(url, CURLUPART_URL, url_text, CURLU_DISALLOW_USER) == CURLUE_OK &&
        curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) == CURLUE_OK &&
        (!strcmp(scheme, "smtp") || !strcmp(scheme, "smtps")) &&
        curl_url_get(url, CURLUPART_HOST, &host, 0) == CURLUE_OK &&
        curl_url_get(url, CURLUPART_QUERY, &query, 0) == CURLUE_NO_QUERY &&
        curl_url_get(url, CURLUPART_FRAGMENT, &fragment, 0) == CURLUE_NO_FRAGMENT;
    if (valid && curl_url_get(url, CURLUPART_PATH, &path, 0) == CURLUE_OK)
        valid = !path[0] || !strcmp(path, "/");
    if (valid) {
        char *copy = canonical_host(host);
        if (!copy) {
            curl_free(scheme); curl_free(host); curl_free(port); curl_free(path);
            curl_free(query); curl_free(fragment); curl_url_cleanup(url);
            return fail(err, n, "Memoria insufficiente per la configurazione SMTP.");
        }
        free(out->host); out->host = copy;
        free(out->security); out->security = strdup(!strcmp(scheme, "smtps") ? "tls" : "starttls");
        out->port = !strcmp(scheme, "smtps") ? 465 : 25;
        CURLUcode port_result = curl_url_get(url, CURLUPART_PORT, &port, 0);
        if (port_result == CURLUE_OK) {
            char *end = NULL;
            long parsed = strtol(port, &end, 10);
            if (!*port || *end || parsed < 1 || parsed > 65535) valid = 0;
            else out->port = (int)parsed;
        } else if (port_result != CURLUE_NO_PORT) valid = 0;
    }
    curl_free(scheme); curl_free(host); curl_free(port); curl_free(path);
    curl_free(query); curl_free(fragment); curl_url_cleanup(url);
    if (!out->security) return fail(err, n, "Memoria insufficiente per la configurazione SMTP.");
    if (!valid) {
        /* Keep metadata readable while making an invalid legacy URL impossible
         * to mistake for an enabled, complete configuration. */
        free(out->host); out->host = strdup("");
        if (!out->host) return fail(err, n, "Memoria insufficiente per la configurazione SMTP.");
    }
    return 1;
}

int smtp_settings_load(Store *store, int with_secret, SmtpSettings *out,
                       char *err, size_t n)
{
    if (err && n) err[0] = '\0';
    if (!out) return fail(err, n, "Configurazione SMTP mancante.");
    if (!basic_settings(out, err, n)) return 0;
    if (!store || !store->db) {
        smtp_settings_free(out);
        return fail(err, n, "Archivio SMTP non aperto.");
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(store->db,
        "SELECT enabled,host,port,security,from_email,username,password_cipher,updated_at "
        "FROM smtp_settings WHERE id=1", -1, &stmt, NULL) != SQLITE_OK) goto fail_db;
    int result = sqlite3_step(stmt);
    if (result == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        int ok = load_environment(out, with_secret, err, n);
        if (!ok) smtp_settings_free(out);
        return ok;
    }
    if (result != SQLITE_ROW) goto fail_db;
    out->exists = 1;
    out->source = "database";
    out->enabled = sqlite3_column_int(stmt, 0);
    free(out->host); out->host = column_text(stmt, 1);
    out->port = sqlite3_column_int(stmt, 2);
    free(out->security); out->security = column_text(stmt, 3);
    free(out->from_email); out->from_email = column_text(stmt, 4);
    free(out->username); out->username = column_text(stmt, 5);
    out->updated_at = sqlite3_column_int64(stmt, 7);
    int cipher_length = sqlite3_column_bytes(stmt, 6);
    out->password_set = cipher_length > 0;
    if (!out->host || !out->security || !out->from_email || !out->username) {
        fail(err, n, "Dati della configurazione SMTP non validi o memoria insufficiente.");
        goto failure;
    }
    if (with_secret && out->password_set &&
        !decrypt_password(store, sqlite3_column_blob(stmt, 6), cipher_length, &out->password, err, n))
        goto failure;
    if (sqlite3_finalize(stmt) != SQLITE_OK) { stmt = NULL; goto fail_db; }
    return 1;

fail_db:
    db_error(store, err, n);
failure:
    sqlite3_finalize(stmt);
    smtp_settings_free(out);
    return 0;
}

int smtp_settings_prepare(Store *store, const SmtpSettings *input,
                          int clear_password, SmtpSettings *resolved,
                          char *err, size_t n)
{
    if (!resolved) return fail(err, n, "Configurazione SMTP mancante.");
    memset(resolved, 0, sizeof *resolved);
    if (!input) return fail(err, n, "Configurazione SMTP mancante.");
    if (clear_password != 0 && clear_password != 1)
        return fail(err, n, "Opzione di rimozione password non valida.");
    if (clear_password && present(input->password))
        return fail(err, n, "Per rimuovere la password lasciare vuoto il campo nuova password.");
    resolved->exists = 1;
    resolved->source = "database";
    resolved->enabled = input->enabled;
    resolved->port = input->port;
    resolved->host = canonical_host(input->host);
    resolved->security = strdup(value(input->security));
    resolved->from_email = strdup(value(input->from_email));
    resolved->username = strdup(value(input->username));
    if (present(input->password)) resolved->password = strdup(input->password);
    if (!resolved->host || !resolved->security || !resolved->from_email || !resolved->username ||
        (present(input->password) && !resolved->password)) {
        fail(err, n, "Memoria insufficiente per la configurazione SMTP.");
        goto failure;
    }
    if (!present(input->password) && !clear_password) {
        SmtpSettings previous;
        if (!smtp_settings_load(store, 0, &previous, err, n)) goto failure;
        int same_account = !strcasecmp(resolved->host, value(previous.host)) &&
            resolved->port == previous.port &&
            !strcmp(resolved->security, value(previous.security)) &&
            !strcmp(resolved->username, value(previous.username));
        if (same_account && previous.password_set) {
            smtp_settings_free(&previous);
            if (!smtp_settings_load(store, 1, &previous, err, n)) goto failure;
            resolved->password = previous.password;
            previous.password = NULL;
        }
        smtp_settings_free(&previous);
    }
    resolved->password_set = present(resolved->password);
    if (!smtp_settings_validate(resolved, 0, err, n)) goto failure;
    return 1;

failure:
    smtp_settings_free(resolved);
    return 0;
}

static unsigned char *encrypt_password(Store *store, const char *password,
                                       int *length, char *err, size_t n)
{
    int size = (int)strlen(password);
    *length = CIPHER_HEADER + size;
    unsigned char *blob = calloc((size_t)*length, 1);
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (!blob || !context) {
        free(blob); EVP_CIPHER_CTX_free(context);
        fail(err, n, "Memoria insufficiente per cifrare la password SMTP.");
        return NULL;
    }
    blob[0] = 1;
    int output = 0, tail = 0;
    int ok = RAND_bytes(blob + 1, NONCE_SIZE) == 1 &&
        EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL) == 1 &&
        EVP_EncryptInit_ex(context, NULL, NULL, store->smtp_key, blob + 1) == 1 &&
        EVP_EncryptUpdate(context, NULL, &output, cipher_aad, sizeof cipher_aad - 1) == 1 &&
        EVP_EncryptUpdate(context, blob + CIPHER_HEADER, &output, (const unsigned char *)password, size) == 1 &&
        EVP_EncryptFinal_ex(context, blob + CIPHER_HEADER + output, &tail) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, blob + 1 + NONCE_SIZE) == 1;
    EVP_CIPHER_CTX_free(context);
    if (!ok || output + tail != size) {
        OPENSSL_cleanse(blob, (size_t)*length); free(blob);
        fail(err, n, "Impossibile cifrare la password SMTP.");
        return NULL;
    }
    return blob;
}

int smtp_settings_save(Store *store, const SmtpSettings *resolved, int64_t now,
                       char *err, size_t n)
{
    if (!store || !store->db) return fail(err, n, "Archivio SMTP non aperto.");
    if (!smtp_settings_validate(resolved, 0, err, n)) return 0;
    if (!!resolved->password_set != !!present(resolved->password))
        return fail(err, n, "Password SMTP non disponibile per il salvataggio.");
    unsigned char *cipher = NULL;
    int cipher_length = 0;
    sqlite3_stmt *stmt = NULL;
    if (present(resolved->password)) {
        if (sqlite3_prepare_v2(store->db,
            "SELECT length(password_cipher) FROM smtp_settings WHERE id=1",
            -1, &stmt, NULL) != SQLITE_OK) return db_error(store, err, n);
        int result = sqlite3_step(stmt);
        if (result != SQLITE_ROW && result != SQLITE_DONE) goto fail_db;
        int has_existing_cipher = result == SQLITE_ROW && sqlite3_column_int(stmt, 0) > 0;
        if (sqlite3_finalize(stmt) != SQLITE_OK) { stmt = NULL; goto fail_db; }
        stmt = NULL;
        if (!encryption_key(store, !has_existing_cipher, err, n)) return 0;
        cipher = encrypt_password(store, resolved->password, &cipher_length, err, n);
        if (!cipher) return 0;
    }
    if (sqlite3_prepare_v2(store->db,
        "INSERT INTO smtp_settings(id,enabled,host,port,security,from_email,username,password_cipher,updated_at) "
        "VALUES(1,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,"
        "host=excluded.host,port=excluded.port,security=excluded.security,from_email=excluded.from_email,"
        "username=excluded.username,password_cipher=excluded.password_cipher,updated_at=excluded.updated_at",
        -1, &stmt, NULL) != SQLITE_OK) goto fail_db;
    if (sqlite3_bind_int(stmt, 1, resolved->enabled) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, value(resolved->host), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 3, resolved->port) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 4, value(resolved->security), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 5, value(resolved->from_email), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 6, value(resolved->username), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        (cipher ? sqlite3_bind_blob(stmt, 7, cipher, cipher_length, SQLITE_TRANSIENT) : sqlite3_bind_null(stmt, 7)) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 8, now) != SQLITE_OK || sqlite3_step(stmt) != SQLITE_DONE) goto fail_db;
    if (sqlite3_finalize(stmt) != SQLITE_OK) { stmt = NULL; goto fail_db; }
    if (cipher) { OPENSSL_cleanse(cipher, (size_t)cipher_length); free(cipher); }
    return 1;

fail_db:
    db_error(store, err, n);
    sqlite3_finalize(stmt);
    if (cipher) { OPENSSL_cleanse(cipher, (size_t)cipher_length); free(cipher); }
    return 0;
}

char *smtp_settings_url(const SmtpSettings *settings, char *err, size_t n)
{
    if (!smtp_settings_validate(settings, 1, err, n)) return NULL;
    int ipv6 = strchr(settings->host, ':') != NULL;
    const char *scheme = !strcmp(settings->security, "tls") ? "smtps" : "smtp";
    size_t length = strlen(settings->host) + 32;
    char *url = malloc(length);
    if (!url) { fail(err, n, "Memoria insufficiente per l'URL SMTP."); return NULL; }
    (void)snprintf(url, length, ipv6 ? "%s://[%s]:%d" : "%s://%s:%d",
                   scheme, settings->host, settings->port);
    return url;
}
