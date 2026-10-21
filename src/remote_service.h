#ifndef REMOTE_SERVICE_H
#define REMOTE_SERVICE_H

#include "store.h"

char *remote_check_json(Store *store, const char *target, int64_t expected_id,
                        size_t *length, int *status, char *error, size_t error_size);
const char *remote_snapshot_pem(const char *token, size_t *length);
const char *remote_snapshot_target(const char *token);
int remote_import_snapshot(Store *store, const char *token, int *imported,
                            int *duplicates, int64_t *certificate_id,
                            char *error, size_t error_size);
void remote_cache_clear(void);

#endif
