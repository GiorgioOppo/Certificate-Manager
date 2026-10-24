#ifndef CERTIFICATI_MAIL_TEMPLATES_H
#define CERTIFICATI_MAIL_TEMPLATES_H
#include "store.h"

const char *mail_templates_schema(void);
const char *mail_templates_schema_v8(void);
int mail_templates_active_language(Store *, const char *alert, const char *audience,
    char language[16], char *err, size_t n);
char *mail_templates_api(Store *, const char *method, const char *path,
    const unsigned char *body, size_t body_len, size_t *response_len,
    int *status, char *err, size_t n);
/* Rendered text is a snapshot owned by the caller. Overrides NULL load the
 * saved/default template. No database writes or sends occur here. */
int mail_templates_render(Store *, const char *alert, const char *audience,
    int64_t certificate_id, int64_t event_id, int threshold, int64_t now,
    const char *recipient_name, const char *recipient_email,
    const char *subject_override, const char *body_override,
    char **subject, char **body, char *err, size_t n);
int mail_templates_render_language(Store *, const char *alert, const char *audience,
    const char *language, int64_t certificate_id, int64_t event_id, int threshold, int64_t now,
    const char *recipient_name, const char *recipient_email,
    const char *subject_override, const char *body_override,
    char **subject, char **body, char *err, size_t n);
const char *mail_templates_expiry_alert(int threshold);
/* Caller owns the returned audience. Self takes precedence over contacts for monitor/escalation routing. */
char *mail_templates_audience(Store *, int64_t certificate_id, const char *email,
    char *err, size_t n);
#endif
