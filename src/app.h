#ifndef APP_H
#define APP_H
#include "store.h"
#include <signal.h>
#include <stdio.h>

extern volatile sig_atomic_t app_running;
int64_t app_days_remaining(int64_t expiry, int64_t now);
const char *app_status(int64_t start, int64_t expiry, int64_t now);
int app_import(Store *store, const char *file, const char *source,
               int *imported, int *duplicates, char *error, size_t error_size);
int app_check(Store *store, int64_t now, int *count, FILE *log,
              char *error, size_t error_size);
int app_renew(Store *store, int64_t old_id, const char *file, const char *source,
              int64_t *new_id, int *queued, char *error, size_t error_size);
int app_distribute(Store *store, int64_t id, int *queued, char *error, size_t error_size);
char *app_state_json(Store *store, const char *token, size_t *length,
                     char *error, size_t error_size);
void app_json_string(FILE *out, const char *value);
int app_serve(Store *store, const char *bind_address, unsigned short port);
#endif
