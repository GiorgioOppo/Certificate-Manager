#ifndef CERTIFICATI_WORKFLOW_SUPPORT_H
#define CERTIFICATI_WORKFLOW_SUPPORT_H
#include "store.h"
#include <stdio.h>
typedef struct { char **keys, **values; size_t count; } WFForm;
int wf_form_parse(const unsigned char *, size_t, WFForm *, char *, size_t);
void wf_form_free(WFForm *);
/* wf_get returns NULL for absent OR duplicate fields. Repeated values use wf_nth. */
const char *wf_get(const WFForm *, const char *);
size_t wf_count(const WFForm *, const char *);
const char *wf_nth(const WFForm *, const char *, size_t);
int wf_number(const char *, int64_t, int64_t, int64_t *);
int wf_json_rows(Store *, FILE *, const char *, int64_t, char *, size_t);
int wf_audit(Store *, const char *, int64_t, const char *, const char *, char *, size_t);
const char *wf_schema(void);
#endif
