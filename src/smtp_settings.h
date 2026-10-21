#ifndef CERTIFICATI_SMTP_SETTINGS_H
#define CERTIFICATI_SMTP_SETTINGS_H

#include "store.h"

typedef struct {
    int exists;
    int enabled;
    int port;
    int password_set;
    char *host;
    char *security;
    char *from_email;
    char *username;
    char *password;
    const char *source;
    int64_t updated_at;
} SmtpSettings;

/* Public loads never return or decrypt the password. Environment configuration
 * is used only until the first database configuration is saved. */
int smtp_settings_load(Store *store, int with_secret, SmtpSettings *out,
                       char *err, size_t n);
int smtp_settings_validate(const SmtpSettings *settings, int require_complete,
                           char *err, size_t n);
/* A blank password retains the previous secret only for the same server and
 * account. Saving and preparing settings never send messages. */
int smtp_settings_prepare(Store *store, const SmtpSettings *input,
                          int clear_password, SmtpSettings *resolved,
                          char *err, size_t n);
int smtp_settings_save(Store *store, const SmtpSettings *resolved, int64_t now,
                       char *err, size_t n);
void smtp_settings_free(SmtpSettings *settings);
/* Caller owns the URL. STARTTLS and implicit TLS are both supported. */
char *smtp_settings_url(const SmtpSettings *settings, char *err, size_t n);

#endif
