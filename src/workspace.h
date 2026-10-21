#ifndef CERTIFICATE_WORKSPACE_H
#define CERTIFICATE_WORKSPACE_H
#include "store.h"
#include <stdio.h>
int workspace_contacts_saved(Store *, int64_t, char *, size_t);
int workspace_save_person(Store *, int64_t, const char *, const char *, const int64_t *, size_t, int64_t *, char *, size_t);
int workspace_save_group(Store *, int64_t, const char *, const int64_t *, size_t, int64_t *, char *, size_t);
int workspace_remove_person(Store *, int64_t, char *, size_t);
int workspace_remove_group(Store *, int64_t, char *, size_t);
int workspace_assign(Store *, int64_t, const char *, const int64_t *, size_t, const int64_t *, size_t, char *, size_t);
int workspace_save_policy(Store *, int64_t, const char *, int, const char *, const char *, int, char *, size_t);
int workspace_monitor_mail(Store *, int64_t, int, const char *, char *, size_t);
int workspace_state_append(Store *, FILE *, char *, size_t);
char *workspace_import_preview(Store *, const char *, const char *, size_t *, char *, size_t);
#endif
