#ifndef CERTIFICATI_INVENTORY_H
#define CERTIFICATI_INVENTORY_H
#include "store.h"
const char *inventory_schema(void);
char *inventory_api(Store *, const char *, const char *, const unsigned char *, size_t,
                    size_t *, int *, char *, size_t);
int inventory_tick(Store *, int64_t, char *, size_t);
void inventory_shutdown(void);
#endif
