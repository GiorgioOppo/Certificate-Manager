#ifndef CERTIFICATI_STORE_H
#define CERTIFICATI_STORE_H

#include <stddef.h>
#include <stdint.h>
#include <sqlite3.h>

#include "certificate.h"

typedef struct {
    sqlite3 *db;
    unsigned char smtp_key[32];
    int smtp_key_loaded;
} Store;

typedef struct {
    const char *role;
    const char *name;
    const char *email;
} StoreContact;

int store_open(Store *store, const char *path, char *err, size_t errlen);
void store_close(Store *store);
int store_exec(Store *store, const char *sql, char *err, size_t errlen);
int store_add(Store *store, const Certificate *cert, const char *source,
              int64_t now, int64_t *id, int *inserted, char *err,
              size_t errlen);
int store_remove(Store *store, int64_t id, int *removed, char *err,
                 size_t errlen);
int store_set_contacts(Store *store, int64_t id, const StoreContact *contacts,
                       size_t count, char *err, size_t errlen);

#endif
