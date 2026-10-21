#ifndef CERTIFICATI_CHAIN_H
#define CERTIFICATI_CHAIN_H

#include "store.h"

typedef struct {
    char *root_ca;
    char *intermediate_ca;
    char *status;
    char *pem_bundle;
} CertificateChain;

int chain_describe(Store *store, int64_t id, CertificateChain *chain,
                    char *err, size_t errlen);
void chain_free(CertificateChain *chain);
int chain_renewal_matches(const Certificate *old_cert, const Certificate *new_cert,
                          char *err, size_t errlen);

#endif
