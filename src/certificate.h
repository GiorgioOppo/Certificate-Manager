#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char *common_name;
    char *subject;
    char *issuer;
    char *serial;
    char *sans;
    char *fingerprint;
    char *key_algorithm;
    char *signature_algorithm;
    char *pem;
    int key_bits;
    int is_ca;
    int64_t not_before;
    int64_t not_after;
} Certificate;

typedef struct {
    Certificate *items;
    size_t count;
} CertificateList;

/* On failure out is empty; the caller owns every string on success. */
int certificate_load_file(const char *path, CertificateList *out,
                          char *error, size_t error_size);
void certificate_list_free(CertificateList *list);

#endif
