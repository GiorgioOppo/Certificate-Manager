#include "chain.h"

#include <arpa/inet.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define CHAIN_MAX_DEPTH 16U
#define CHAIN_MAX_CANDIDATES 8192U
#define CHAIN_SEARCH_BUDGET 131072U

typedef struct {
    int64_t id;
    X509 *x509;
    char *pem;
    char *subject;
    int is_ca;
} Candidate;

typedef struct {
    Candidate *items;
    size_t count;
    size_t best[CHAIN_MAX_DEPTH];
    size_t best_count;
    size_t budget;
    int complete;
} Search;

typedef struct {
    char *data;
    size_t size;
} String;

static void error_text(char *err, size_t size, const char *message)
{
    if (err != NULL && size != 0)
        (void)snprintf(err, size, "%s", message);
}

static char *duplicate(const char *value)
{
    size_t length = strlen(value);
    char *result = malloc(length + 1);
    if (result != NULL)
        memcpy(result, value, length + 1);
    return result;
}

static int append(String *output, const char *value, const char *separator)
{
    size_t length = strlen(value);
    size_t gap = output->size != 0 ? strlen(separator) : 0;
    char *next;
    if (length > SIZE_MAX - output->size - gap - 1)
        return 0;
    next = realloc(output->data, output->size + gap + length + 1);
    if (next == NULL)
        return 0;
    output->data = next;
    if (gap != 0)
        memcpy(output->data + output->size, separator, gap);
    memcpy(output->data + output->size + gap, value, length + 1);
    output->size += gap + length;
    return 1;
}

static char *pem_text(X509 *x509)
{
    BIO *bio = BIO_new(BIO_s_mem());
    char *data = NULL;
    char *result = NULL;
    long length;
    if (bio == NULL)
        return NULL;
    if (PEM_write_bio_X509(bio, x509) != 1)
        goto done;
    length = BIO_get_mem_data(bio, &data);
    if (length > 0) {
        result = malloc((size_t)length + 1);
        if (result != NULL) {
            memcpy(result, data, (size_t)length);
            result[length] = '\0';
        }
    }
done:
    BIO_free(bio);
    return result;
}

static char *subject_text(X509 *x509)
{
    BIO *bio = BIO_new(BIO_s_mem());
    char *data = NULL;
    char *result = NULL;
    long length;
    if (bio == NULL)
        return NULL;
    if (X509_NAME_print_ex(bio, X509_get_subject_name(x509), 0, XN_FLAG_RFC2253) < 0)
        goto done;
    length = BIO_get_mem_data(bio, &data);
    if (length >= 0) {
        /* RFC2253 escapes name controls; defend against controls from any backend. */
        size_t written = 0;
        if ((size_t)length > (SIZE_MAX - 1) / 4)
            goto done;
        result = malloc((size_t)length * 4 + 1);
        if (result == NULL)
            goto done;
        for (long i = 0; i < length; ++i) {
            unsigned char c = (unsigned char)data[i];
            if (c < 32 || c >= 127) {
                (void)snprintf(result + written, 5, "\\x%02X", c);
                written += 4;
            }
            else {
                result[written++] = (char)c;
            }
        }
        result[written] = '\0';
    }
done:
    BIO_free(bio);
    return result;
}

static X509 *parse_pem(const char *pem, size_t length)
{
    BIO *bio;
    X509 *x509;
    if (pem == NULL || length == 0 || length > INT_MAX || memchr(pem, 0, length) != NULL)
        return NULL;
    bio = BIO_new_mem_buf(pem, (int)length);
    if (bio == NULL)
        return NULL;
    x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    ERR_clear_error();
    return x509;
}

static void candidates_free(Search *search)
{
    for (size_t i = 0; i < search->count; ++i) {
        X509_free(search->items[i].x509);
        free(search->items[i].pem);
        free(search->items[i].subject);
    }
    free(search->items);
}

static int signature_valid(X509 *child, X509 *issuer)
{
    EVP_PKEY *key;
    int valid;
    if (X509_NAME_cmp(X509_get_issuer_name(child), X509_get_subject_name(issuer)) != 0 ||
        X509_check_issued(issuer, child) != X509_V_OK)
        return 0;
    key = X509_get_pubkey(issuer);
    if (key == NULL) {
        ERR_clear_error();
        return 0;
    }
    valid = X509_verify(child, key) == 1;
    EVP_PKEY_free(key);
    ERR_clear_error();
    return valid;
}

static int self_signed(Candidate *candidate)
{
    return candidate->is_ca && signature_valid(candidate->x509, candidate->x509);
}

static void search_path(Search *search, size_t path[CHAIN_MAX_DEPTH], size_t depth)
{
    Candidate *child = &search->items[path[depth - 1]];
    if (depth > search->best_count) {
        memcpy(search->best, path, depth * sizeof(path[0]));
        search->best_count = depth;
    }
    if (self_signed(child)) {
        memcpy(search->best, path, depth * sizeof(path[0]));
        search->best_count = depth;
        search->complete = 1;
        return;
    }
    if (depth == CHAIN_MAX_DEPTH || search->budget == 0)
        return;
    for (size_t i = 0; i < search->count && !search->complete && search->budget != 0; ++i) {
        Candidate *issuer = &search->items[i];
        int visited = 0;
        if (!issuer->is_ca || X509_NAME_cmp(X509_get_issuer_name(child->x509),
                                           X509_get_subject_name(issuer->x509)) != 0)
            continue;
        for (size_t j = 0; j < depth; ++j) {
            if (path[j] == i || X509_cmp(search->items[path[j]].x509, issuer->x509) == 0) {
                visited = 1;
                break;
            }
        }
        if (visited)
            continue;
        --search->budget;
        if (!signature_valid(child->x509, issuer->x509))
            continue;
        path[depth] = i;
        search_path(search, path, depth + 1);
    }
}

void chain_free(CertificateChain *chain)
{
    if (chain == NULL)
        return;
    free(chain->root_ca);
    free(chain->intermediate_ca);
    free(chain->status);
    free(chain->pem_bundle);
    memset(chain, 0, sizeof(*chain));
}

int chain_describe(Store *store, int64_t id, CertificateChain *chain,
                    char *err, size_t errlen)
{
    sqlite3_stmt *stmt = NULL;
    Search search = {0};
    size_t leaf = SIZE_MAX;
    size_t path[CHAIN_MAX_DEPTH];
    int target_found = 0;
    int legacy = 0;
    int rc;
    String bundle = {0};
    String intermediates = {0};
    if (chain == NULL)
        return 0;
    memset(chain, 0, sizeof(*chain));
    error_text(err, errlen, "");
    if (store == NULL || store->db == NULL || id <= 0) {
        error_text(err, errlen, "Certificato o archivio non valido.");
        return 0;
    }
    if (sqlite3_prepare_v2(store->db, "SELECT length(pem) FROM certificates WHERE id=?",
        -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int64(stmt, 1, id) != SQLITE_OK)
        goto database_failure;
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        error_text(err, errlen, "Certificato non trovato.");
        goto failure;
    }
    if (rc != SQLITE_ROW)
        goto database_failure;
    if (sqlite3_column_int64(stmt, 0) == 0) {
        chain->root_ca = duplicate("");
        chain->intermediate_ca = duplicate("");
        chain->status = duplicate("legacy");
        chain->pem_bundle = duplicate("");
        sqlite3_finalize(stmt);
        stmt = NULL;
        if (chain->root_ca == NULL || chain->intermediate_ca == NULL ||
            chain->status == NULL || chain->pem_bundle == NULL)
            goto memory_failure;
        return 1;
    }
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (sqlite3_prepare_v2(store->db,
        "SELECT id,pem FROM certificates WHERE id=? OR (is_ca<>0 AND pem<>'') ORDER BY id",
        -1, &stmt, NULL) != SQLITE_OK || sqlite3_bind_int64(stmt, 1, id) != SQLITE_OK)
        goto database_failure;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int64_t candidate_id = sqlite3_column_int64(stmt, 0);
        const char *stored = (const char *)sqlite3_column_text(stmt, 1);
        int length = sqlite3_column_bytes(stmt, 1);
        X509 *x509;
        Candidate candidate;
        Candidate *next;
        if (candidate_id == id) {
            target_found = 1;
            if (stored == NULL || length == 0) {
                legacy = 1;
                continue;
            }
        }
        x509 = parse_pem(stored, (size_t)length);
        if (x509 == NULL) {
            if (candidate_id == id) {
                error_text(err, errlen, "Il PEM archiviato del certificato non e valido.");
                goto failure;
            }
            continue;
        }
        if (search.count >= CHAIN_MAX_CANDIDATES) {
            X509_free(x509);
            error_text(err, errlen, "Troppi certificati CA per ricostruire la catena (massimo 8192).");
            goto failure;
        }
        memset(&candidate, 0, sizeof(candidate));
        candidate.id = candidate_id;
        candidate.x509 = x509;
        candidate.pem = pem_text(x509);
        candidate.subject = subject_text(x509);
        candidate.is_ca = X509_check_ca(x509) > 0;
        next = realloc(search.items, (search.count + 1) * sizeof(*next));
        if (candidate.pem == NULL || candidate.subject == NULL || next == NULL) {
            /* realloc may have moved the array even if another allocation failed. */
            if (next != NULL) search.items = next;
            X509_free(candidate.x509);
            free(candidate.pem);
            free(candidate.subject);
            goto memory_failure;
        }
        search.items = next;
        if (candidate_id == id)
            leaf = search.count;
        search.items[search.count++] = candidate;
    }
    if (rc != SQLITE_DONE)
        goto database_failure;
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (!target_found) {
        error_text(err, errlen, "Certificato non trovato.");
        goto failure;
    }
    chain->root_ca = duplicate("");
    if (legacy) {
        chain->intermediate_ca = duplicate("");
        chain->pem_bundle = duplicate("");
        chain->status = duplicate("legacy");
    } else {
        if (leaf == SIZE_MAX)
            goto memory_failure;
        path[0] = leaf;
        search.budget = CHAIN_SEARCH_BUDGET;
        search_path(&search, path, 1);
        chain->status = duplicate(search.complete ? "complete" : "incomplete");
        if (search.complete) {
            free(chain->root_ca);
            chain->root_ca = duplicate(search.items[search.best[search.best_count - 1]].subject);
        }
        for (size_t i = 0; i < search.best_count; ++i) {
            Candidate *candidate = &search.items[search.best[i]];
            if (!append(&bundle, candidate->pem, ""))
                goto memory_failure;
            if ((i != 0 || candidate->is_ca) &&
                !(search.complete && i + 1 == search.best_count) &&
                !append(&intermediates, candidate->subject, "\n"))
                goto memory_failure;
        }
        chain->pem_bundle = bundle.data != NULL ? bundle.data : duplicate("");
        chain->intermediate_ca = intermediates.data != NULL ? intermediates.data : duplicate("");
        bundle.data = intermediates.data = NULL;
    }
    if (chain->root_ca == NULL || chain->intermediate_ca == NULL ||
        chain->status == NULL || chain->pem_bundle == NULL)
        goto memory_failure;
    candidates_free(&search);
    return 1;
database_failure:
    error_text(err, errlen, sqlite3_errmsg(store->db));
    goto failure;
memory_failure:
    error_text(err, errlen, "Memoria insufficiente per ricostruire la catena.");
failure:
    sqlite3_finalize(stmt);
    candidates_free(&search);
    free(bundle.data);
    free(intermediates.data);
    chain_free(chain);
    return 0;
}

static int ascii_case_equal(const char *a, const char *b)
{
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a++;
        unsigned char cb = (unsigned char)*b++;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + 32);
        if (ca != cb) return 0;
    }
    return *a == *b;
}

typedef struct {
    char **items;
    size_t count;
} Identities;

static void identities_free(Identities *identities)
{
    for (size_t i = 0; i < identities->count; ++i)
        free(identities->items[i]);
    free(identities->items);
}

static int identity_add(Identities *identities, const char *value)
{
    char **next;
    char *copy;
    for (size_t i = 0; i < identities->count; ++i)
        if (ascii_case_equal(identities->items[i], value))
            return 1;
    copy = duplicate(value);
    if (copy == NULL)
        return 0;
    next = realloc(identities->items, (identities->count + 1) * sizeof(*next));
    if (next == NULL) {
        free(copy);
        return 0;
    }
    identities->items = next;
    identities->items[identities->count++] = copy;
    return 1;
}

static int identity_string(Identities *identities, const char *prefix,
                           const unsigned char *value, size_t length)
{
    size_t prefix_length = strlen(prefix);
    char *token;
    int ok;
    if (length == 0 || length > SIZE_MAX - prefix_length - 1)
        return 0;
    for (size_t i = 0; i < length; ++i) {
        if (value[i] <= 32 || value[i] >= 127 || value[i] == ',' || value[i] == '\\')
            return 0;
    }
    token = malloc(prefix_length + length + 1);
    if (token == NULL)
        return 0;
    memcpy(token, prefix, prefix_length);
    memcpy(token + prefix_length, value, length);
    token[prefix_length + length] = '\0';
    ok = identity_add(identities, token);
    free(token);
    return ok;
}

static int pem_identities(X509 *x509, Identities *identities)
{
    int critical = -1;
    int ok = 1;
    GENERAL_NAMES *names = X509_get_ext_d2i(x509, NID_subject_alt_name, &critical, NULL);
    if (names == NULL && critical != -1)
        return 0;
    for (int i = 0; names != NULL && i < sk_GENERAL_NAME_num(names) && ok; ++i) {
        GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
        if (name->type == GEN_DNS) {
            int length = ASN1_STRING_length(name->d.dNSName);
            ok = length > 0 && identity_string(identities, "DNS:",
                ASN1_STRING_get0_data(name->d.dNSName), (size_t)length);
        } else if (name->type == GEN_IPADD) {
            int length = ASN1_STRING_length(name->d.iPAddress);
            char address[INET6_ADDRSTRLEN];
            if ((length != 4 && length != 16) || inet_ntop(length == 4 ? AF_INET : AF_INET6,
                ASN1_STRING_get0_data(name->d.iPAddress), address, sizeof(address)) == NULL)
                ok = 0;
            else
                ok = identity_string(identities, "IP:", (const unsigned char *)address, strlen(address));
        }
    }
    GENERAL_NAMES_free(names);
    if (!ok)
        return 0;
    if (identities->count == 0) {
        const X509_NAME *subject = X509_get_subject_name(x509);
        int index = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
        unsigned char *utf8 = NULL;
        int length;
        if (index < 0)
            return 0;
        length = ASN1_STRING_to_UTF8(&utf8,
            X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, index)));
        ok = length > 0 && identity_string(identities, "CN:", utf8, (size_t)length);
        OPENSSL_free(utf8);
    }
    return ok;
}

static int certificate_identities(const Certificate *certificate, Identities *identities)
{
    if (certificate->pem != NULL && certificate->pem[0] != '\0') {
        X509 *x509 = parse_pem(certificate->pem, strlen(certificate->pem));
        int ok;
        if (x509 == NULL)
            return 0;
        ok = pem_identities(x509, identities);
        X509_free(x509);
        return ok;
    }
    /* Legacy rows have no PEM: compare the normalized importer metadata. */
    const char *cursor = certificate->sans != NULL ? certificate->sans : "";
    while (*cursor) {
        const char *end = strstr(cursor, ", ");
        size_t length = end != NULL ? (size_t)(end - cursor) : strlen(cursor);
        char *token;
        if (length == 0 || (strncmp(cursor, "DNS:", 4) != 0 && strncmp(cursor, "IP:", 3) != 0))
            return 0;
        token = malloc(length + 1);
        if (token == NULL)
            return 0;
        memcpy(token, cursor, length);
        token[length] = '\0';
        int ok = identity_add(identities, token);
        free(token);
        if (!ok)
            return 0;
        if (end == NULL)
            break;
        cursor = end + 2;
    }
    if (identities->count == 0) {
        if (certificate->common_name == NULL || certificate->common_name[0] == '\0' ||
            strcmp(certificate->common_name, "Certificato senza nome") == 0)
            return 0;
        return identity_string(identities, "CN:",
            (const unsigned char *)certificate->common_name, strlen(certificate->common_name));
    }
    return 1;
}

int chain_renewal_matches(const Certificate *old_cert, const Certificate *new_cert,
                          char *err, size_t errlen)
{
    Identities old_ids = {0};
    Identities new_ids = {0};
    int matches = 0;
    error_text(err, errlen, "");
    if (old_cert == NULL || new_cert == NULL ||
        !certificate_identities(old_cert, &old_ids) ||
        !certificate_identities(new_cert, &new_ids)) {
        error_text(err, errlen, "Impossibile confrontare le identita DNS/IP dei certificati.");
        goto done;
    }
    if (old_ids.count != new_ids.count)
        goto mismatch;
    for (size_t i = 0; i < old_ids.count; ++i) {
        int found = 0;
        for (size_t j = 0; j < new_ids.count; ++j)
            if (ascii_case_equal(old_ids.items[i], new_ids.items[j])) {
                found = 1;
                break;
            }
        if (!found)
            goto mismatch;
    }
    matches = 1;
    goto done;
mismatch:
    error_text(err, errlen, "Il certificato rinnovato deve mantenere le stesse identita DNS/IP o lo stesso CN.");
done:
    identities_free(&old_ids);
    identities_free(&new_ids);
    return matches;
}
