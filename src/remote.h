#ifndef CERTIFICATI_REMOTE_H
#define CERTIFICATI_REMOTE_H

#include "certificate.h"

typedef struct {
    char *target;
    char *host;
    char *address;
    char *tls_version;
    char *verification_error;
    char *pem_bundle;
    int port;
    int dns_ok;
    int tcp_ok;
    int tls_ok;
    int chain_trusted;
    int hostname_valid;
    int time_valid;
    int verified;
    int64_t checked_at;
    CertificateList certificates;
} RemoteResult;

/* A processed network/TLS failure returns 1 with diagnostic fields set.
 * Return 0 for invalid input, resource failures or local configuration errors.
 * Only the TLS handshake is performed; no HTTP/application data is sent.
 * chain_trusted is normal path verification, including validity dates;
 * time_valid reports the leaf certificate's own validity interval.
 * The caller owns all returned allocations and must use remote_result_free. */
int remote_fetch(const char *input, RemoteResult *out, char *err, size_t errlen);
/* Validate and normalize an endpoint without making a network connection. */
int remote_normalize_target(const char *input, char **canonical, char *err, size_t errlen);
void remote_result_free(RemoteResult *result);

#endif
