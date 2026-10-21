#include "certificate.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define MAX_CERTIFICATE_FILE (16U * 1024U * 1024U)
#define MAX_CERTIFICATES 1024U

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} Text;

static void set_error(char *error, size_t size, const char *format, ...)
{
    va_list args;
    if (error == NULL || size == 0)
        return;
    va_start(args, format);
    (void)vsnprintf(error, size, format, args);
    va_end(args);
}

static int append_text(Text *text, const char *data, size_t length)
{
    size_t needed;
    size_t capacity;
    char *next;
    if (length > SIZE_MAX - text->length - 1)
        return 0;
    needed = text->length + length + 1;
    if (needed > text->capacity) {
        capacity = text->capacity != 0 ? text->capacity : 64;
        while (capacity < needed) {
            if (capacity > SIZE_MAX / 2) {
                capacity = needed;
                break;
            }
            capacity *= 2;
        }
        next = realloc(text->data, capacity);
        if (next == NULL)
            return 0;
        text->data = next;
        text->capacity = capacity;
    }
    if (length != 0)
        memcpy(text->data + text->length, data, length);
    text->length += length;
    text->data[text->length] = '\0';
    return 1;
}

static char *copy_text(const char *value)
{
    size_t length = strlen(value);
    char *copy = malloc(length + 1);
    if (copy != NULL)
        memcpy(copy, value, length + 1);
    return copy;
}

/* Keep terminal output ASCII and escape all controls, including ESC and DEL. */
static char *safe_text(const unsigned char *value, size_t length)
{
    static const char hex[] = "0123456789ABCDEF";
    Text output = {0};
    size_t i;
    for (i = 0; i < length; ++i) {
        unsigned char c = value[i];
        if (c == 0) {
            free(output.data);
            return NULL;
        }
        if (c < 32 || c >= 127) {
            char escaped[] = {'\\', 'x', hex[c >> 4], hex[c & 15]};
            if (!append_text(&output, escaped, sizeof(escaped)))
                goto failure;
        } else if (!append_text(&output, (const char *)&value[i], 1)) {
            goto failure;
        }
    }
    if (output.data == NULL)
        return copy_text("");
    return output.data;
failure:
    free(output.data);
    return NULL;
}

static int string_has_no_nul(const ASN1_STRING *value)
{
    unsigned char *utf8 = NULL;
    int length;
    int valid;
    if (value == NULL)
        return 0;
    length = ASN1_STRING_to_UTF8(&utf8, value);
    if (length < 0)
        return 0;
    valid = length == 0 || memchr(utf8, 0, (size_t)length) == NULL;
    OPENSSL_free(utf8);
    return valid;
}

static int name_has_no_nul(const X509_NAME *name)
{
    int i;
    if (name == NULL)
        return 0;
    for (i = 0; i < X509_NAME_entry_count(name); ++i) {
        const X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, i);
        if (entry == NULL || !string_has_no_nul(X509_NAME_ENTRY_get_data(entry)))
            return 0;
    }
    return 1;
}

static char *name_text(const X509_NAME *name)
{
    BIO *bio = BIO_new(BIO_s_mem());
    char *data = NULL;
    char *result = NULL;
    long length;
    if (bio == NULL)
        return NULL;
    if (X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253) < 0)
        goto done;
    length = BIO_get_mem_data(bio, &data);
    if (length >= 0)
        result = safe_text((const unsigned char *)data, (size_t)length);
done:
    BIO_free(bio);
    return result;
}

static char *common_name_text(const X509_NAME *name)
{
    int index = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    unsigned char *utf8 = NULL;
    char *result;
    int length;
    if (index < 0)
        return copy_text("");
    length = ASN1_STRING_to_UTF8(&utf8,
        X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, index)));
    if (length < 0)
        return NULL;
    result = safe_text(utf8, (size_t)length);
    OPENSSL_free(utf8);
    return result;
}

static int append_san(Text *output, const char *prefix, const char *value)
{
    if (output->length != 0 && !append_text(output, ", ", 2))
        return 0;
    return append_text(output, prefix, strlen(prefix)) &&
           append_text(output, value, strlen(value));
}

static int san_strings_valid(const GENERAL_NAME *name)
{
    const ASN1_TYPE *other;
    switch (name->type) {
    case GEN_EMAIL:
    case GEN_DNS:
    case GEN_URI:
        return string_has_no_nul(name->d.ia5);
    case GEN_DIRNAME:
        return name_has_no_nul(name->d.directoryName);
    case GEN_EDIPARTY:
        return name->d.ediPartyName != NULL &&
            (name->d.ediPartyName->nameAssigner == NULL ||
             string_has_no_nul(name->d.ediPartyName->nameAssigner)) &&
            string_has_no_nul(name->d.ediPartyName->partyName);
    case GEN_OTHERNAME:
        if (name->d.otherName == NULL || name->d.otherName->value == NULL)
            return 0;
        other = name->d.otherName->value;
        switch (ASN1_TYPE_get(other)) {
        case V_ASN1_UTF8STRING:
        case V_ASN1_NUMERICSTRING:
        case V_ASN1_PRINTABLESTRING:
        case V_ASN1_T61STRING:
        case V_ASN1_IA5STRING:
        case V_ASN1_GENERALSTRING:
        case V_ASN1_UNIVERSALSTRING:
        case V_ASN1_BMPSTRING:
            return string_has_no_nul(other->value.asn1_string);
        default:
            return 1;
        }
    default:
        return 1;
    }
}

static int extract_sans(X509 *x509, char **sans, char **first_dns,
                        char *error, size_t error_size)
{
    GENERAL_NAMES *names;
    Text output = {0};
    int critical = -1;
    int i;
    names = X509_get_ext_d2i(x509, NID_subject_alt_name, &critical, NULL);
    if (names == NULL) {
        if (critical != -1) {
            set_error(error, error_size, "Estensione SAN malformata o duplicata.");
            return 0;
        }
        *sans = copy_text("");
        return *sans != NULL;
    }
    for (i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
        GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
        char *value = NULL;
        const char *prefix = NULL;
        if (name == NULL || !san_strings_valid(name)) {
            set_error(error, error_size, "SAN non valido: testo malformato o caratteri NUL.");
            goto failure;
        }
        if (name->type == GEN_DNS) {
            int length = ASN1_STRING_length(name->d.dNSName);
            if (length <= 0) {
                set_error(error, error_size, "Il certificato contiene un SAN DNS vuoto.");
                goto failure;
            }
            value = safe_text(ASN1_STRING_get0_data(name->d.dNSName), (size_t)length);
            prefix = "DNS:";
            if (value != NULL && *first_dns == NULL) {
                *first_dns = copy_text(value);
                if (*first_dns == NULL) {
                    free(value);
                    goto failure;
                }
            }
        } else if (name->type == GEN_IPADD) {
            int length = ASN1_STRING_length(name->d.iPAddress);
            char address[INET6_ADDRSTRLEN];
            int family = length == 4 ? AF_INET : AF_INET6;
            if ((length != 4 && length != 16) ||
                inet_ntop(family, ASN1_STRING_get0_data(name->d.iPAddress),
                          address, sizeof(address)) == NULL) {
                set_error(error, error_size, "Il certificato contiene un SAN IP non valido.");
                goto failure;
            }
            value = copy_text(address);
            prefix = "IP:";
        }
        if (prefix != NULL && (value == NULL || !append_san(&output, prefix, value))) {
            free(value);
            goto failure;
        }
        free(value);
    }
    GENERAL_NAMES_free(names);
    *sans = output.data != NULL ? output.data : copy_text("");
    return *sans != NULL;
failure:
    free(output.data);
    GENERAL_NAMES_free(names);
    return 0;
}

/* Gregorian calendar conversion, independent of the host timezone/time_t width. */
static int time_to_epoch(const ASN1_TIME *value, int64_t *result)
{
    struct tm tm_value;
    int year;
    int month;
    int era;
    unsigned int year_of_era;
    unsigned int day_of_year;
    unsigned int day_of_era;
    int64_t days;
    memset(&tm_value, 0, sizeof(tm_value));
    if (value == NULL || ASN1_TIME_to_tm(value, &tm_value) != 1)
        return 0;
    year = tm_value.tm_year + 1900;
    month = tm_value.tm_mon + 1;
    if (year < 0 || year > 9999 || month < 1 || month > 12 ||
        tm_value.tm_mday < 1 || tm_value.tm_mday > 31 ||
        tm_value.tm_hour < 0 || tm_value.tm_hour > 23 ||
        tm_value.tm_min < 0 || tm_value.tm_min > 59 ||
        tm_value.tm_sec < 0 || tm_value.tm_sec > 59)
        return 0;
    year -= month <= 2;
    era = (year >= 0 ? year : year - 399) / 400;
    year_of_era = (unsigned int)(year - era * 400);
    day_of_year = (153U * (unsigned int)(month + (month > 2 ? -3 : 9)) + 2U) / 5U +
                  (unsigned int)tm_value.tm_mday - 1U;
    day_of_era = year_of_era * 365U + year_of_era / 4U - year_of_era / 100U + day_of_year;
    days = (int64_t)era * 146097 + day_of_era - 719468;
    *result = days * 86400 + tm_value.tm_hour * 3600 + tm_value.tm_min * 60 + tm_value.tm_sec;
    return 1;
}

static void certificate_free(Certificate *certificate)
{
    free(certificate->common_name);
    free(certificate->subject);
    free(certificate->issuer);
    free(certificate->serial);
    free(certificate->sans);
    free(certificate->fingerprint);
    free(certificate->key_algorithm);
    free(certificate->signature_algorithm);
    free(certificate->pem);
    memset(certificate, 0, sizeof(*certificate));
}

void certificate_list_free(CertificateList *list)
{
    size_t i;
    if (list == NULL)
        return;
    for (i = 0; i < list->count; ++i)
        certificate_free(&list->items[i]);
    free(list->items);
    list->items = NULL;
    list->count = 0;
}

static char *signature_name(X509 *x509)
{
    const X509_ALGOR *algorithm = NULL;
    const ASN1_OBJECT *object = NULL;
    const char *name = OBJ_nid2ln(X509_get_signature_nid(x509));
    char oid[128];
    int length;
    if (name != NULL)
        return copy_text(name);
    X509_get0_signature(NULL, &algorithm, x509);
    if (algorithm == NULL)
        return NULL;
    X509_ALGOR_get0(&object, NULL, NULL, algorithm);
    if (object == NULL)
        return NULL;
    length = OBJ_obj2txt(oid, sizeof(oid), object, 1);
    if (length <= 0 || (size_t)length >= sizeof(oid))
        return NULL;
    return copy_text(oid);
}

static char *normalized_pem(X509 *x509)
{
    BIO *bio = BIO_new(BIO_s_mem());
    char *data = NULL;
    char *copy = NULL;
    long length;
    if (bio == NULL)
        return NULL;
    if (PEM_write_bio_X509(bio, x509) != 1)
        goto done;
    length = BIO_get_mem_data(bio, &data);
    if (length > 0) {
        copy = malloc((size_t)length + 1);
        if (copy != NULL) {
            memcpy(copy, data, (size_t)length);
            copy[length] = '\0';
        }
    }
done:
    BIO_free(bio);
    return copy;
}

static int extract_certificate(X509 *x509, Certificate *certificate,
                               char *error, size_t error_size)
{
    EVP_PKEY *key = NULL;
    BIGNUM *serial_number = NULL;
    char *openssl_serial = NULL;
    char *first_dns = NULL;
    const char *key_name;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    unsigned int i;
    static const char hex[] = "0123456789ABCDEF";
    BASIC_CONSTRAINTS *constraints = NULL;
    int critical = -1;
    memset(certificate, 0, sizeof(*certificate));
    if (!name_has_no_nul(X509_get_subject_name(x509)) ||
        !name_has_no_nul(X509_get_issuer_name(x509))) {
        set_error(error, error_size, "Nome del certificato malformato o contenente caratteri NUL.");
        goto failure;
    }
    if (!time_to_epoch(X509_get0_notBefore(x509), &certificate->not_before) ||
        !time_to_epoch(X509_get0_notAfter(x509), &certificate->not_after) ||
        certificate->not_before > certificate->not_after) {
        set_error(error, error_size, "Date di validita del certificato non valide.");
        goto failure;
    }
    certificate->subject = name_text(X509_get_subject_name(x509));
    certificate->issuer = name_text(X509_get_issuer_name(x509));
    certificate->common_name = common_name_text(X509_get_subject_name(x509));
    if (certificate->subject == NULL || certificate->issuer == NULL ||
        certificate->common_name == NULL)
        goto failure;
    if (!extract_sans(x509, &certificate->sans, &first_dns, error, error_size))
        goto failure;
    if (certificate->common_name[0] == '\0') {
        free(certificate->common_name);
        if (first_dns != NULL) {
            certificate->common_name = first_dns;
            first_dns = NULL;
        } else {
            certificate->common_name = copy_text(certificate->subject[0] != '\0' ?
                certificate->subject : "Certificato senza nome");
        }
    }
    free(first_dns);
    first_dns = NULL;
    serial_number = ASN1_INTEGER_to_BN(X509_get0_serialNumber(x509), NULL);
    if (serial_number != NULL)
        openssl_serial = BN_bn2hex(serial_number);
    if (openssl_serial != NULL)
        certificate->serial = copy_text(openssl_serial);
    if (X509_digest(x509, EVP_sha256(), digest, &digest_length) != 1 || digest_length != 32) {
        set_error(error, error_size, "Impossibile calcolare l'impronta SHA-256.");
        goto failure;
    }
    certificate->fingerprint = malloc((size_t)digest_length * 2 + 1);
    if (certificate->fingerprint == NULL)
        goto failure;
    for (i = 0; i < digest_length; ++i) {
        certificate->fingerprint[i * 2] = hex[digest[i] >> 4];
        certificate->fingerprint[i * 2 + 1] = hex[digest[i] & 15];
    }
    certificate->fingerprint[digest_length * 2] = '\0';
    key = X509_get_pubkey(x509);
    if (key == NULL) {
        set_error(error, error_size, "Chiave pubblica del certificato malformata o non supportata.");
        goto failure;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    key_name = EVP_PKEY_get0_type_name(key);
#else
    key_name = OBJ_nid2ln(EVP_PKEY_base_id(key));
#endif
    if (key_name == NULL) {
        set_error(error, error_size, "Algoritmo della chiave pubblica non riconosciuto.");
        goto failure;
    }
    certificate->key_algorithm = copy_text(key_name);
    certificate->key_bits = EVP_PKEY_bits(key);
    certificate->signature_algorithm = signature_name(x509);
    certificate->pem = normalized_pem(x509);
    constraints = X509_get_ext_d2i(x509, NID_basic_constraints, &critical, NULL);
    if (constraints == NULL && critical != -1) {
        set_error(error, error_size, "Estensione basicConstraints malformata o duplicata.");
        goto failure;
    }
    certificate->is_ca = constraints != NULL ? constraints->ca != 0 : X509_check_ca(x509) > 0;
    if (certificate->common_name == NULL || certificate->serial == NULL ||
        certificate->key_algorithm == NULL || certificate->signature_algorithm == NULL ||
        certificate->pem == NULL)
        goto failure;
    BASIC_CONSTRAINTS_free(constraints);
    OPENSSL_free(openssl_serial);
    BN_free(serial_number);
    EVP_PKEY_free(key);
    return 1;
failure:
    BASIC_CONSTRAINTS_free(constraints);
    OPENSSL_free(openssl_serial);
    BN_free(serial_number);
    EVP_PKEY_free(key);
    free(first_dns);
    certificate_free(certificate);
    return 0;
}

static int add_der(CertificateList *list, const unsigned char *data, size_t length,
                   char *error, size_t error_size)
{
    const unsigned char *cursor = data;
    X509 *x509;
    Certificate certificate;
    Certificate *items;
    if (list->count >= MAX_CERTIFICATES) {
        set_error(error, error_size, "Il file supera il limite di %u certificati.", MAX_CERTIFICATES);
        return 0;
    }
    if (length == 0 || length > LONG_MAX) {
        set_error(error, error_size, "Dimensione del certificato DER non valida.");
        return 0;
    }
    ERR_clear_error();
    x509 = d2i_X509(NULL, &cursor, (long)length);
    if (x509 == NULL || cursor != data + length) {
        X509_free(x509);
        set_error(error, error_size, "Certificato DER malformato o contenente dati aggiuntivi.");
        return 0;
    }
    if (!extract_certificate(x509, &certificate, error, error_size)) {
        X509_free(x509);
        return 0;
    }
    X509_free(x509);
    items = realloc(list->items, (list->count + 1) * sizeof(*items));
    if (items == NULL) {
        certificate_free(&certificate);
        return 0;
    }
    list->items = items;
    list->items[list->count++] = certificate;
    return 1;
}

static int ascii_space(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

static int base64_character(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/';
}

static unsigned int base64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z')
        return (unsigned int)(c - 'A');
    if (c >= 'a' && c <= 'z')
        return (unsigned int)(c - 'a') + 26U;
    if (c >= '0' && c <= '9')
        return (unsigned int)(c - '0') + 52U;
    return c == '+' ? 62U : 63U;
}

static int add_pem_block(CertificateList *list, const char *start, const char *end,
                         char *error, size_t error_size)
{
    const char *p;
    unsigned char *base64 = NULL;
    unsigned char *der = NULL;
    size_t length = 0;
    size_t padding = 0;
    int decoded;
    int ok = 0;
    base64 = malloc((size_t)(end - start) + 1);
    if (base64 == NULL)
        goto done;
    for (p = start; p < end; ++p) {
        unsigned char c = (unsigned char)*p;
        if (ascii_space(c))
            continue;
        if (!base64_character(c) && c != '=') {
            set_error(error, error_size, "Blocco PEM malformato: dati Base64 non validi.");
            goto done;
        }
        base64[length++] = c;
    }
    if (length == 0 || length % 4 != 0 || length > INT_MAX) {
        set_error(error, error_size, "Blocco PEM malformato: lunghezza Base64 non valida.");
        goto done;
    }
    if (base64[length - 1] == '=')
        ++padding;
    if (base64[length - 2] == '=')
        ++padding;
    for (p = (const char *)base64; p < (const char *)base64 + length - padding; ++p) {
        if (*p == '=') {
            set_error(error, error_size, "Blocco PEM malformato: padding Base64 non valido.");
            goto done;
        }
    }
    if ((padding == 1 && (base64_value(base64[length - 2]) & 3U) != 0) ||
        (padding == 2 && (base64_value(base64[length - 3]) & 15U) != 0)) {
        set_error(error, error_size, "Blocco PEM malformato: bit di padding Base64 non validi.");
        goto done;
    }
    base64[length] = '\0';
    der = malloc(length / 4 * 3);
    if (der == NULL)
        goto done;
    decoded = EVP_DecodeBlock(der, base64, (int)length);
    if (decoded < 0 || (size_t)decoded < padding) {
        set_error(error, error_size, "Blocco PEM malformato: decodifica Base64 fallita.");
        goto done;
    }
    ok = add_der(list, der, (size_t)decoded - padding, error, error_size);
done:
    free(base64);
    free(der);
    return ok;
}

static int load_pem(const unsigned char *data, size_t length, CertificateList *list,
                    char *error, size_t error_size)
{
    static const char begin_marker[] = "-----BEGIN CERTIFICATE-----";
    static const char end_marker[] = "-----END CERTIFICATE-----";
    const char *cursor = (const char *)data;
    const char *limit = cursor + length;
    if (memchr(data, 0, length) != NULL) {
        set_error(error, error_size, "Il file PEM contiene caratteri NUL.");
        return 0;
    }
    while (cursor < limit) {
        const char *end;
        while (cursor < limit && ascii_space((unsigned char)*cursor))
            ++cursor;
        if (cursor == limit)
            break;
        if ((size_t)(limit - cursor) < sizeof(begin_marker) - 1 ||
            memcmp(cursor, begin_marker, sizeof(begin_marker) - 1) != 0) {
            set_error(error, error_size, "Il PEM deve contenere solo blocchi CERTIFICATE completi e spazi.");
            return 0;
        }
        cursor += sizeof(begin_marker) - 1;
        if (cursor == limit || (*cursor != '\r' && *cursor != '\n')) {
            set_error(error, error_size, "Intestazione PEM non valida.");
            return 0;
        }
        end = strstr(cursor, end_marker);
        if (end == NULL) {
            set_error(error, error_size, "Blocco PEM incompleto: manca END CERTIFICATE.");
            return 0;
        }
        if (!add_pem_block(list, cursor, end, error, error_size))
            return 0;
        cursor = end + sizeof(end_marker) - 1;
        if (cursor < limit && !ascii_space((unsigned char)*cursor)) {
            set_error(error, error_size, "Dati inattesi dopo END CERTIFICATE.");
            return 0;
        }
    }
    if (list->count == 0) {
        set_error(error, error_size, "Il file non contiene certificati.");
        return 0;
    }
    return 1;
}

int certificate_load_file(const char *path, CertificateList *out,
                          char *error, size_t error_size)
{
    FILE *file = NULL;
    unsigned char *data = NULL;
    size_t length;
    size_t first = 0;
    int ok = 0;
    CertificateList list = {0};
    if (error != NULL && error_size != 0)
        error[0] = '\0';
    if (out == NULL) {
        set_error(error, error_size, "Percorso del certificato non valido.");
        return 0;
    }
    out->items = NULL;
    out->count = 0;
    if (path == NULL || path[0] == '\0') {
        set_error(error, error_size, "Percorso del certificato non valido.");
        return 0;
    }
    file = fopen(path, "rb");
    if (file == NULL) {
        set_error(error, error_size, "Impossibile aprire il certificato: %s.", strerror(errno));
        return 0;
    }
    data = malloc((size_t)MAX_CERTIFICATE_FILE + 1);
    if (data == NULL)
        goto done;
    length = fread(data, 1, (size_t)MAX_CERTIFICATE_FILE + 1, file);
    if (ferror(file)) {
        set_error(error, error_size, "Errore durante la lettura del certificato.");
        goto done;
    }
    if (length > MAX_CERTIFICATE_FILE) {
        set_error(error, error_size, "Il file supera il limite di 16 MiB.");
        goto done;
    }
    if (length == 0) {
        set_error(error, error_size, "Il file del certificato e vuoto.");
        goto done;
    }
    data[length] = '\0';
    while (first < length && ascii_space(data[first]))
        ++first;
    if (first < length && data[first] == '-')
        ok = load_pem(data, length, &list, error, error_size);
    else
        ok = add_der(&list, data, length, error, error_size);
done:
    free(data);
    (void)fclose(file);
    ERR_clear_error();
    if (ok) {
        *out = list;
    } else {
        certificate_list_free(&list);
        if (error != NULL && error_size != 0 && error[0] == '\0')
            set_error(error, error_size, "Memoria insufficiente o dati del certificato non validi.");
    }
    return ok;
}
