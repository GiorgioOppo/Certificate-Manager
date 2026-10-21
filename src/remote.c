#define _POSIX_C_SOURCE 200809L
#include "remote.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#define REMOTE_TIMEOUT_MS 10000
#define REMOTE_MAX_ADDRESSES 32U
#define REMOTE_MAX_CHAIN 32U
#define REMOTE_MAX_PEM (16U * 1024U * 1024U)
#define REMOTE_MAX_INPUT 4096U
#define REMOTE_MAX_ERRORS 64U

typedef struct {
    struct sockaddr_storage address;
    socklen_t length;
} ResolvedAddress;

typedef struct {
    int error;
    size_t count;
    ResolvedAddress addresses[REMOTE_MAX_ADDRESSES];
} Resolution;

typedef struct {
    int errors[REMOTE_MAX_ERRORS];
    size_t count;
    int overflow;
} VerificationNotes;

typedef struct {
    char *data;
    size_t size;
} Text;

static void error_text(char *err, size_t n, const char *message)
{
    if (err != NULL && n != 0)
        (void)snprintf(err, n, "%s", message);
}

static char *duplicate(const char *text)
{
    size_t length = strlen(text);
    char *result = malloc(length + 1);
    if (result != NULL)
        memcpy(result, text, length + 1);
    return result;
}

static int diagnostic(RemoteResult *out, const char *message)
{
    char *copy = duplicate(message);
    if (copy == NULL)
        return 0;
    free(out->verification_error);
    out->verification_error = copy;
    return 1;
}

static int append(Text *text, const char *value)
{
    size_t length = strlen(value);
    size_t gap = text->size != 0 ? 1 : 0;
    char *next;
    if (length > SIZE_MAX - text->size - gap - 1)
        return 0;
    next = realloc(text->data, text->size + gap + length + 1);
    if (next == NULL)
        return 0;
    text->data = next;
    if (gap != 0)
        text->data[text->size++] = ' ';
    memcpy(text->data + text->size, value, length + 1);
    text->size += length;
    return 1;
}

static int64_t monotonic_ms(void)
{
    struct timespec time_value;
    if (clock_gettime(CLOCK_MONOTONIC, &time_value) != 0)
        return -1;
    return (int64_t)time_value.tv_sec * 1000 + time_value.tv_nsec / 1000000;
}

static int wait_ready(struct pollfd *fds, nfds_t count, int64_t deadline)
{
    for (;;) {
        int64_t now = monotonic_ms();
        int64_t remaining;
        int result;
        if (now < 0)
            return -1;
        remaining = deadline - now;
        if (remaining <= 0)
            return 0;
        result = poll(fds, count, remaining > INT_MAX ? INT_MAX : (int)remaining);
        if (result < 0 && errno == EINTR)
            continue;
        return result;
    }
}

static int ascii_alnum(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

static int dns_host_valid(const char *host)
{
    const char *label = host;
    size_t length = strlen(host);
    if (length == 0 || length > 253)
        return 0;
    for (const char *p = host;; ++p) {
        unsigned char c = (unsigned char)*p;
        if (c == '.' || c == 0) {
            size_t label_length = (size_t)(p - label);
            if (label_length == 0 || label_length > 63 ||
                !ascii_alnum((unsigned char)label[0]) || !ascii_alnum((unsigned char)p[-1]))
                return 0;
            if (c == 0)
                return 1;
            label = p + 1;
        } else if (!ascii_alnum(c) && c != '-') {
            return 0;
        }
    }
}

static int parse_target(const char *input, RemoteResult *out, int *ip_literal,
                         char *err, size_t n)
{
    size_t length;
    const char *authority;
    const char *end;
    const char *port_text = NULL;
    size_t host_length;
    char host[256];
    unsigned char ip[16];
    int family = 0;
    int port = 443;
    int has_scheme = 0;
    char target[320];
    if (input == NULL || (length = strnlen(input, REMOTE_MAX_INPUT + 1)) == 0 ||
        length > REMOTE_MAX_INPUT) {
        error_text(err, n, "Inserisci un URL HTTPS o un nome host (massimo 4096 byte).");
        return 0;
    }
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)input[i];
        if (c <= 32 || c == 127) {
            error_text(err, n, "L'indirizzo non puo contenere spazi o caratteri di controllo.");
            return 0;
        }
    }
    authority = input;
    if (strncasecmp(input, "https://", 8) == 0) {
        authority += 8;
        has_scheme = 1;
    } else if (strstr(input, "://") != NULL || strncasecmp(input, "http:", 5) == 0) {
        error_text(err, n, "Per il controllo dei certificati usa HTTPS, per esempio https://example.it.");
        return 0;
    }
    end = authority + strcspn(authority, "/?#");
    if (!has_scheme && *end != '\0') {
        error_text(err, n, "Per includere un percorso usa un URL completo che inizi con https://.");
        return 0;
    }
    if (memchr(authority, '@', (size_t)(end - authority)) != NULL) {
        error_text(err, n, "Inserisci un indirizzo senza credenziali (utente o password).");
        return 0;
    }
    if (memchr(authority, '*', (size_t)(end - authority)) != NULL) {
        error_text(err, n, "Un CN wildcard non e un server: sostituisci * con un host concreto, per esempio www.example.it.");
        return 0;
    }
    if (authority < end && *authority == '[') {
        const char *closing = memchr(authority, ']', (size_t)(end - authority));
        if (closing == NULL || closing == authority + 1 ||
            (closing + 1 < end && closing[1] != ':'))
            goto invalid_host;
        host_length = (size_t)(closing - authority - 1);
        if (host_length >= sizeof(host))
            goto invalid_host;
        memcpy(host, authority + 1, host_length);
        host[host_length] = '\0';
        if (inet_pton(AF_INET6, host, ip) != 1)
            goto invalid_host;
        family = AF_INET6;
        if (closing + 1 < end)
            port_text = closing + 2;
    } else {
        const char *colon = memchr(authority, ':', (size_t)(end - authority));
        host_length = (size_t)(end - authority);
        if (colon != NULL) {
            /* A bare IPv6 literal is accepted only without a port. */
            if (host_length < sizeof(host)) {
                memcpy(host, authority, host_length);
                host[host_length] = '\0';
                if (inet_pton(AF_INET6, host, ip) == 1)
                    family = AF_INET6;
            }
            if (family == 0) {
                host_length = (size_t)(colon - authority);
                port_text = colon + 1;
            }
        }
        if (host_length == 0 || host_length >= sizeof(host))
            goto invalid_host;
        memcpy(host, authority, host_length);
        host[host_length] = '\0';
        if (family == 0 && inet_pton(AF_INET, host, ip) == 1)
            family = AF_INET;
        if (family == 0) {
            if (host_length > 1 && host[host_length - 1] == '.')
                host[--host_length] = '\0';
            if (!dns_host_valid(host))
                goto invalid_host;
            for (size_t i = 0; i < host_length; ++i)
                if (host[i] >= 'A' && host[i] <= 'Z') host[i] = (char)(host[i] + 32);
        }
    }
    if (port_text != NULL) {
        unsigned int value = 0;
        if (port_text == end)
            goto invalid_port;
        for (const char *p = port_text; p < end; ++p) {
            if (*p < '0' || *p > '9')
                goto invalid_port;
            value = value * 10 + (unsigned int)(*p - '0');
            if (value > 65535)
                goto invalid_port;
        }
        if (value == 0)
            goto invalid_port;
        port = (int)value;
    }
    if (family != 0 && inet_ntop(family, ip, host, sizeof(host)) == NULL)
        goto invalid_host;
    (void)snprintf(target, sizeof(target), family == AF_INET6 ? "https://[%s]:%d" : "https://%s:%d", host, port);
    out->host = duplicate(host);
    out->target = duplicate(target);
    out->port = port;
    *ip_literal = family != 0;
    if (out->host == NULL || out->target == NULL) {
        error_text(err, n, "Memoria insufficiente per l'indirizzo remoto.");
        return 0;
    }
    return 1;
invalid_host:
    error_text(err, n, "Nome host non valido: usa un nome ASCII/punycode, un IPv4 o un IPv6 tra parentesi quadre.");
    return 0;
invalid_port:
    error_text(err, n, "Porta non valida: usa un numero da 1 a 65535.");
    return 0;
}

static void reap_resolver(pid_t pid, int terminate)
{
    if (terminate)
        (void)kill(pid, SIGKILL);
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
}

/* DNS is isolated so the operating system resolver cannot block this probe. */
static int resolve_host(const char *host, int port, int ip_literal, int64_t deadline,
                         Resolution *resolution, RemoteResult *out, char *err, size_t n)
{
    int fds[2];
    pid_t child;
    size_t received = 0;
    if (pipe(fds) != 0) {
        error_text(err, n, "Impossibile creare il canale per la risoluzione DNS.");
        return 0;
    }
    child = fork();
    if (child < 0) {
        close(fds[0]); close(fds[1]);
        error_text(err, n, "Impossibile avviare la risoluzione DNS.");
        return 0;
    }
    if (child == 0) {
        Resolution message;
        struct addrinfo hints;
        struct addrinfo *addresses = NULL;
        char service[8];
        size_t written = 0;
        close(fds[0]);
        memset(&message, 0, sizeof(message));
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_NUMERICSERV | (ip_literal ? AI_NUMERICHOST : 0);
        (void)snprintf(service, sizeof(service), "%d", port);
        message.error = getaddrinfo(host, service, &hints, &addresses);
        if (message.error == 0) {
            for (struct addrinfo *p = addresses; p != NULL && message.count < REMOTE_MAX_ADDRESSES; p = p->ai_next) {
                if ((p->ai_family == AF_INET || p->ai_family == AF_INET6) &&
                    p->ai_addrlen <= sizeof(struct sockaddr_storage)) {
                    ResolvedAddress *entry = &message.addresses[message.count++];
                    memcpy(&entry->address, p->ai_addr, p->ai_addrlen);
                    entry->length = (socklen_t)p->ai_addrlen;
                }
            }
            freeaddrinfo(addresses);
            if (message.count == 0)
                message.error = EAI_NONAME;
        }
        while (written < sizeof(message)) {
            ssize_t result = write(fds[1], (const unsigned char *)&message + written, sizeof(message) - written);
            if (result < 0 && errno == EINTR)
                continue;
            if (result <= 0)
                break;
            written += (size_t)result;
        }
        close(fds[1]);
        _exit(written == sizeof(message) ? 0 : 1);
    }
    close(fds[1]);
    while (received < sizeof(*resolution)) {
        struct pollfd ready = {fds[0], POLLIN, 0};
        int status = wait_ready(&ready, 1, deadline);
        ssize_t count;
        if (status <= 0) {
            close(fds[0]);
            reap_resolver(child, 1);
            if (status < 0) {
                error_text(err, n, "Errore locale durante l'attesa del DNS.");
                return 0;
            }
            return diagnostic(out, "Risoluzione DNS non completata entro il limite di 10 secondi.") ? -1 : 0;
        }
        count = read(fds[0], (unsigned char *)resolution + received, sizeof(*resolution) - received);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            close(fds[0]);
            reap_resolver(child, 1);
            error_text(err, n, "Il processo di risoluzione DNS si e interrotto.");
            return 0;
        }
        received += (size_t)count;
    }
    close(fds[0]);
    reap_resolver(child, 0);
    if (resolution->error != 0 || resolution->count == 0) {
        char message[512];
        if (resolution->error == EAI_MEMORY) {
            error_text(err, n, "Memoria insufficiente durante la risoluzione DNS.");
            return 0;
        }
        (void)snprintf(message, sizeof(message), "Risoluzione DNS non riuscita: %s.",
                       gai_strerror(resolution->error != 0 ? resolution->error : EAI_NONAME));
        return diagnostic(out, message) ? -1 : 0;
    }
    out->dns_ok = 1;
    return 1;
}

static int connect_addresses(const Resolution *resolution, int64_t deadline,
                              RemoteResult *out, char *err, size_t n)
{
    struct pollfd sockets[REMOTE_MAX_ADDRESSES];
    int selected = -1;
    int last_error = ECONNREFUSED;
    int attempted = 0;
    int local_error = 0;
    for (size_t i = 0; i < REMOTE_MAX_ADDRESSES; ++i) {
        sockets[i].fd = -1;
        sockets[i].events = POLLOUT;
        sockets[i].revents = 0;
    }
    for (size_t i = 0; i < resolution->count; ++i) {
        int fd = socket(resolution->addresses[i].address.ss_family, SOCK_STREAM, IPPROTO_TCP);
        int flags;
        if (fd < 0) {
            last_error = errno;
            continue;
        }
        flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            last_error = errno;
            close(fd);
            continue;
        }
#ifdef SO_NOSIGPIPE
        {
            int enabled = 1;
            (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
        }
#endif
        sockets[i].fd = fd;
        attempted = 1;
        if (connect(fd, (const struct sockaddr *)&resolution->addresses[i].address,
                    resolution->addresses[i].length) == 0) {
            selected = (int)i;
            break;
        }
        if (errno != EINPROGRESS && errno != EWOULDBLOCK && errno != EINTR) {
            last_error = errno;
            close(fd);
            sockets[i].fd = -1;
        }
    }
    while (selected < 0) {
        int pending = 0;
        for (size_t i = 0; i < resolution->count; ++i)
            pending += sockets[i].fd >= 0;
        if (!pending)
            break;
        int status = wait_ready(sockets, (nfds_t)resolution->count, deadline);
        if (status <= 0) {
            last_error = status == 0 ? ETIMEDOUT : errno;
            local_error = status < 0;
            break;
        }
        for (size_t i = 0; i < resolution->count; ++i) {
            if (sockets[i].fd >= 0 && sockets[i].revents != 0) {
                int socket_error = 0;
                socklen_t size = sizeof(socket_error);
                if (getsockopt(sockets[i].fd, SOL_SOCKET, SO_ERROR, &socket_error, &size) == 0 && socket_error == 0) {
                    selected = (int)i;
                    break;
                }
                last_error = socket_error != 0 ? socket_error : errno;
                close(sockets[i].fd);
                sockets[i].fd = -1;
            }
        }
    }
    for (size_t i = 0; i < resolution->count; ++i)
        if (sockets[i].fd >= 0 && (int)i != selected)
            close(sockets[i].fd);
    if (selected < 0) {
        char message[512];
        if (!attempted || local_error) {
            error_text(err, n, "Impossibile creare o gestire i socket per il controllo TCP.");
            return -2;
        }
        (void)snprintf(message, sizeof(message), "Connessione TCP non riuscita: %s.", strerror(last_error));
        if (!diagnostic(out, message)) {
            error_text(err, n, "Memoria insufficiente per l'esito TCP.");
            return -2;
        }
        return -1;
    }
    {
        const struct sockaddr_storage *address = &resolution->addresses[selected].address;
        char numeric[INET6_ADDRSTRLEN];
        const void *bytes = address->ss_family == AF_INET ?
            (const void *)&((const struct sockaddr_in *)address)->sin_addr :
            (const void *)&((const struct sockaddr_in6 *)address)->sin6_addr;
        if (inet_ntop(address->ss_family, bytes, numeric, sizeof(numeric)) == NULL ||
            (out->address = duplicate(numeric)) == NULL) {
            close(sockets[selected].fd);
            error_text(err, n, "Impossibile memorizzare l'indirizzo IP remoto.");
            return -2;
        }
    }
    out->tcp_ok = 1;
    return sockets[selected].fd;
}

static void note_error(VerificationNotes *notes, int error)
{
    for (size_t i = 0; i < notes->count; ++i)
        if (notes->errors[i] == error)
            return;
    if (notes->count < REMOTE_MAX_ERRORS)
        notes->errors[notes->count++] = error;
    else
        notes->overflow = 1;
}

static int collect_verification_errors(int preverified, X509_STORE_CTX *context)
{
    SSL *ssl = X509_STORE_CTX_get_ex_data(context, SSL_get_ex_data_X509_STORE_CTX_idx());
    VerificationNotes *notes = ssl != NULL ? SSL_get_app_data(ssl) : NULL;
    if (!preverified && notes != NULL)
        note_error(notes, X509_STORE_CTX_get_error(context));
    /* Diagnostic-only connection: collect the public certificate, never send
     * application data. Trust is independently verified before reporting success. */
    return 1;
}

static int handshake(SSL *ssl, int fd, int64_t deadline, RemoteResult *out)
{
    for (;;) {
        int result;
        int ssl_error;
        int64_t now = monotonic_ms();
        if (now < 0)
            return 0;
        if (now >= deadline)
            return diagnostic(out, "Handshake TLS non completato entro il limite di 10 secondi.") ? -1 : 0;
        ERR_clear_error();
        result = SSL_connect(ssl);
        if (result == 1)
            return 1;
        ssl_error = SSL_get_error(ssl, result);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            struct pollfd ready = {fd, ssl_error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, 0};
            int ready_status = wait_ready(&ready, 1, deadline);
            if (ready_status > 0)
                continue;
            if (ready_status < 0)
                return 0;
            return diagnostic(out, "Handshake TLS non completato entro il limite di 10 secondi.") ? -1 : 0;
        }
        {
            unsigned long code = ERR_get_error();
            const char *reason = code != 0 ? ERR_reason_error_string(code) : NULL;
            char message[512];
            (void)snprintf(message, sizeof(message), "Handshake TLS non riuscito: %s.",
                reason != NULL ? reason : "il server ha chiuso la connessione o non offre TLS compatibile");
            return diagnostic(out, message) ? -1 : 0;
        }
    }
}

static int add_peer(STACK_OF(X509) *certificates, X509 *certificate,
                     unsigned char fingerprints[REMOTE_MAX_CHAIN][32], size_t *count)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (certificate == NULL || X509_digest(certificate, EVP_sha256(), digest, &length) != 1 || length != 32)
        return 0;
    for (size_t i = 0; i < *count; ++i)
        if (memcmp(fingerprints[i], digest, 32) == 0)
            return 1;
    if (*count >= REMOTE_MAX_CHAIN || X509_up_ref(certificate) != 1)
        return 0;
    if (!sk_X509_push(certificates, certificate)) {
        X509_free(certificate);
        return 0;
    }
    memcpy(fingerprints[*count], digest, 32);
    ++*count;
    return 1;
}

/* Returns -1 for certificate data exceeding limits, 0 for a local error. */
static int extract_certificates(STACK_OF(X509) *served, RemoteResult *out,
                                 char *err, size_t n)
{
    BIO *bio = BIO_new(BIO_s_mem());
    char *data = NULL;
    long length;
    char temporary[] = "/tmp/certificati-remote-XXXXXX";
    int fd = -1;
    int created = 0;
    int ok = 0;
    size_t written = 0;
    if (bio == NULL)
        goto memory_failure;
    for (int i = 0; i < sk_X509_num(served); ++i) {
        X509 *certificate = sk_X509_value(served, i);
        int der_length = i2d_X509(certificate, NULL);
        size_t encoded;
        long current = BIO_get_mem_data(bio, &data);
        if (der_length <= 0 || current < 0)
            goto memory_failure;
        encoded = ((size_t)der_length + 2) / 3 * 4;
        if (encoded + encoded / 64 + 128 > REMOTE_MAX_PEM - (size_t)current) {
            ok = diagnostic(out, "La catena presentata dal server supera il limite di 16 MiB.") ? -1 : 0;
            goto done;
        }
        if (PEM_write_bio_X509(bio, certificate) != 1)
            goto memory_failure;
    }
    length = BIO_get_mem_data(bio, &data);
    if (length <= 0 || (size_t)length > REMOTE_MAX_PEM)
        goto memory_failure;
    out->pem_bundle = malloc((size_t)length + 1);
    if (out->pem_bundle == NULL)
        goto memory_failure;
    memcpy(out->pem_bundle, data, (size_t)length);
    out->pem_bundle[length] = '\0';
    fd = mkstemp(temporary);
    if (fd < 0) {
        error_text(err, n, "Impossibile creare il file temporaneo per il certificato remoto.");
        goto done;
    }
    created = 1;
    while (written < (size_t)length) {
        ssize_t count = write(fd, data + written, (size_t)length - written);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            error_text(err, n, "Impossibile scrivere il certificato remoto temporaneo.");
            goto done;
        }
        written += (size_t)count;
    }
    if (close(fd) != 0) {
        fd = -1;
        error_text(err, n, "Impossibile completare il certificato remoto temporaneo.");
        goto done;
    }
    fd = -1;
    if (!certificate_load_file(temporary, &out->certificates, err, n)) {
        char message[768];
        (void)snprintf(message, sizeof(message), "Dati del certificato remoto non importabili: %s", err != NULL && n != 0 ? err : "formato non valido");
        ok = diagnostic(out, message) ? -1 : 0;
        free(out->pem_bundle);
        out->pem_bundle = NULL;
        if (ok != 0) error_text(err, n, "");
        goto done;
    }
    ok = 1;
    goto done;
memory_failure:
    error_text(err, n, "Memoria insufficiente per i certificati presentati dal server.");
done:
    if (fd >= 0) close(fd);
    if (created) unlink(temporary);
    BIO_free(bio);
    return ok;
}

static int verify_peer(SSL_CTX *tls_context, X509 *leaf, STACK_OF(X509) *served,
                        int ip_literal, const VerificationNotes *notes,
                        RemoteResult *out, char *err, size_t n)
{
    X509_STORE_CTX *context = X509_STORE_CTX_new();
    X509_VERIFY_PARAM *parameters;
    Text problems = {0};
    int verified;
    int chain_error;
    if (context == NULL || X509_STORE_CTX_init(context, SSL_CTX_get_cert_store(tls_context), leaf, served) != 1)
        goto failure;
    parameters = X509_STORE_CTX_get0_param(context);
    if (parameters == NULL || X509_VERIFY_PARAM_set_purpose(parameters, X509_PURPOSE_SSL_SERVER) != 1)
        goto failure;
    X509_VERIFY_PARAM_set_depth(parameters, REMOTE_MAX_CHAIN);
    X509_VERIFY_PARAM_set_auth_level(parameters, SSL_CTX_get_security_level(tls_context));
    verified = X509_verify_cert(context);
    if (verified < 0)
        goto failure;
    out->chain_trusted = verified == 1;
    chain_error = X509_STORE_CTX_get_error(context);
    out->hostname_valid = (ip_literal ? X509_check_ip_asc(leaf, out->host, 0) :
        X509_check_host(leaf, out->host, 0, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS, NULL)) == 1;
    out->time_valid = out->certificates.count != 0 &&
        out->certificates.items[0].not_before <= out->checked_at &&
        out->certificates.items[0].not_after > out->checked_at;
    if (!out->chain_trusted) {
        char message[512];
        (void)snprintf(message, sizeof(message), "Catena non attendibile: %s.", X509_verify_cert_error_string(chain_error));
        if (!append(&problems, message))
            goto failure;
    }
    if (!out->hostname_valid && !append(&problems, "Il nome host o indirizzo IP non corrisponde al certificato."))
        goto failure;
    if (!out->time_valid && !append(&problems, "Il certificato e scaduto, non ancora valido o contiene date non valide."))
        goto failure;
    for (size_t i = 0; i < notes->count; ++i) {
        int code = notes->errors[i];
        if (code == chain_error || code == X509_V_ERR_CERT_HAS_EXPIRED || code == X509_V_ERR_CERT_NOT_YET_VALID)
            continue;
        char message[512];
        (void)snprintf(message, sizeof(message), "Verifica TLS: %s.", X509_verify_cert_error_string(code));
        if (!append(&problems, message))
            goto failure;
    }
    if (notes->overflow && !append(&problems, "Ulteriori errori di verifica TLS non elencati."))
        goto failure;
    out->verified = out->chain_trusted && out->hostname_valid && out->time_valid && problems.size == 0;
    if (!diagnostic(out, problems.data != NULL ? problems.data : ""))
        goto failure;
    free(problems.data);
    X509_STORE_CTX_free(context);
    return 1;
failure:
    free(problems.data);
    X509_STORE_CTX_free(context);
    error_text(err, n, "Impossibile completare la verifica del certificato remoto.");
    return 0;
}

void remote_result_free(RemoteResult *result)
{
    if (result == NULL)
        return;
    free(result->target);
    free(result->host);
    free(result->address);
    free(result->tls_version);
    free(result->verification_error);
    free(result->pem_bundle);
    certificate_list_free(&result->certificates);
    memset(result, 0, sizeof(*result));
}

int remote_normalize_target(const char *input, char **canonical, char *err, size_t n)
{
    RemoteResult result = {0};
    int ip_literal = 0;
    if (!canonical) { error_text(err, n, "Destinazione non valida."); return 0; }
    *canonical = NULL;
    int ok = parse_target(input, &result, &ip_literal, err, n);
    if (ok) { *canonical = result.target; result.target = NULL; }
    remote_result_free(&result);
    return ok;
}

int remote_fetch(const char *input, RemoteResult *out, char *err, size_t n)
{
    Resolution resolution;
    VerificationNotes notes = {0};
    SSL_CTX *context = NULL;
    SSL *ssl = NULL;
    X509 *leaf = NULL;
    STACK_OF(X509) *served = NULL;
    STACK_OF(X509) *peer_chain;
    unsigned char fingerprints[REMOTE_MAX_CHAIN][32];
    size_t count = 0;
    int fd = -1;
    int ip_literal = 0;
    int ok = 0;
    int status;
    int64_t start;
    int64_t deadline;
    const char *custom_ca;
    error_text(err, n, "");
    if (out == NULL) {
        error_text(err, n, "Risultato remoto non valido.");
        return 0;
    }
    memset(out, 0, sizeof(*out));
    memset(&resolution, 0, sizeof(resolution));
    if (!parse_target(input, out, &ip_literal, err, n))
        goto done;
    out->checked_at = (int64_t)time(NULL);
    start = monotonic_ms();
    if (start < 0) {
        error_text(err, n, "Orologio monotono non disponibile per il controllo remoto.");
        goto done;
    }
    deadline = start + REMOTE_TIMEOUT_MS;
    status = resolve_host(out->host, out->port, ip_literal, deadline, &resolution, out, err, n);
    if (status <= 0) {
        ok = status == -1;
        goto done;
    }
    fd = connect_addresses(&resolution, deadline, out, err, n);
    if (fd < 0) {
        ok = fd == -1;
        goto done;
    }
    context = SSL_CTX_new(TLS_client_method());
    if (context == NULL || SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION) != 1 ||
        SSL_CTX_set_default_verify_paths(context) != 1) {
        error_text(err, n, "Impossibile inizializzare TLS o caricare le CA predefinite.");
        goto done;
    }
    custom_ca = getenv("CERTIFICATI_TLS_CA_FILE");
    if (custom_ca != NULL && custom_ca[0] != '\0' &&
        SSL_CTX_load_verify_locations(context, custom_ca, NULL) != 1) {
        error_text(err, n, "Il file CA configurato in CERTIFICATI_TLS_CA_FILE non e valido o leggibile.");
        goto done;
    }
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, collect_verification_errors);
    SSL_CTX_set_verify_depth(context, REMOTE_MAX_CHAIN);
    SSL_CTX_set_max_cert_list(context, REMOTE_MAX_PEM);
    ssl = SSL_new(context);
    if (ssl == NULL || SSL_set_fd(ssl, fd) != 1 ||
        (!ip_literal && SSL_set_tlsext_host_name(ssl, out->host) != 1)) {
        error_text(err, n, "Impossibile preparare la connessione TLS remota.");
        goto done;
    }
    if (SSL_set_app_data(ssl, &notes) != 1)
        goto memory_failure;
    status = handshake(ssl, fd, deadline, out);
    if (status <= 0) {
        ok = status == -1;
        goto done;
    }
    out->tls_ok = 1;
    out->tls_version = duplicate(SSL_get_version(ssl));
    if (out->tls_version == NULL)
        goto memory_failure;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    leaf = SSL_get1_peer_certificate(ssl);
#else
    leaf = SSL_get_peer_certificate(ssl);
#endif
    if (leaf == NULL) {
        ok = diagnostic(out, "Il server TLS non ha presentato un certificato pubblico.");
        goto done;
    }
    peer_chain = SSL_get_peer_cert_chain(ssl);
    if (peer_chain != NULL && sk_X509_num(peer_chain) > (int)REMOTE_MAX_CHAIN) {
        ok = diagnostic(out, "Il server presenta piu di 32 certificati nella catena.");
        goto done;
    }
    served = sk_X509_new_null();
    if (served == NULL || !add_peer(served, leaf, fingerprints, &count))
        goto memory_failure;
    for (int i = 0; peer_chain != NULL && i < sk_X509_num(peer_chain); ++i)
        if (!add_peer(served, sk_X509_value(peer_chain, i), fingerprints, &count))
            goto memory_failure;
    status = extract_certificates(served, out, err, n);
    if (status <= 0) {
        ok = status == -1;
        goto done;
    }
    ok = verify_peer(context, leaf, served, ip_literal, &notes, out, err, n);
    goto done;
memory_failure:
    error_text(err, n, "Memoria insufficiente durante il controllo TLS.");
done:
    sk_X509_pop_free(served, X509_free);
    X509_free(leaf);
    SSL_free(ssl);
    SSL_CTX_free(context);
    if (fd >= 0) close(fd);
    ERR_clear_error();
    if (!ok) {
        if (err != NULL && n != 0 && err[0] == '\0')
            error_text(err, n, "Memoria insufficiente o errore locale durante il controllo remoto.");
        remote_result_free(out);
    }
    return ok;
}
