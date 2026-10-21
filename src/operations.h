#ifndef CERTIFICATI_OPERATIONS_H
#define CERTIFICATI_OPERATIONS_H
#include "store.h"
const char *operations_schema(void);
char *operations_api(Store *, const char *, const char *, const unsigned char *, size_t, size_t *, int *, char *, size_t);
/* Within the caller's transaction, before moving services or archiving. */
int operations_capture_report(Store *, int64_t, const char *, char *, size_t);
#endif
