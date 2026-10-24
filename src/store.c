#include "store.h"
#include "workflow_support.h"
#include "inventory.h"
#include "operations.h"
#include "incident.h"
#include "mail_templates.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#define STORE_SCHEMA_VERSION 7

static void set_error(char *err, size_t errlen, const char *message)
{
    if (err != NULL && errlen > 0) {
        (void)snprintf(err, errlen, "%s", message);
    }
}

static int db_error(Store *store, char *err, size_t errlen)
{
    set_error(err, errlen, sqlite3_errmsg(store->db));
    return 0;
}

int store_exec(Store *store, const char *sql, char *err, size_t errlen)
{
    char *message = NULL;
    int rc;

    if (store == NULL || store->db == NULL || sql == NULL) {
        set_error(err, errlen, "Database non aperto o comando non valido.");
        return 0;
    }
    rc = sqlite3_exec(store->db, sql, NULL, NULL, &message);
    if (rc != SQLITE_OK) {
        set_error(err, errlen,
                  message != NULL ? message : sqlite3_errmsg(store->db));
        sqlite3_free(message);
        return 0;
    }
    sqlite3_free(message);
    return 1;
}

static int schema_version(Store *store, int *version, char *err, size_t errlen)
{
    sqlite3_stmt *stmt = NULL;
    int rc;

    if (sqlite3_prepare_v2(store->db, "PRAGMA user_version", -1, &stmt,
                           NULL) != SQLITE_OK) {
        return db_error(store, err, errlen);
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        (void)db_error(store, err, errlen);
        sqlite3_finalize(stmt);
        return 0;
    }
    *version = sqlite3_column_int(stmt, 0);
    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        return db_error(store, err, errlen);
    }
    return 1;
}

static int validate_schema(Store *store, int version, char *err, size_t errlen)
{
    static const char *const queries[] = {
        "SELECT id,fingerprint,common_name,subject,issuer,serial,sans,"
        "key_algorithm,key_bits,signature_algorithm,is_ca,not_before,not_after,"
        "source,added_at FROM certificates LIMIT 0",
        "SELECT certificate_id,threshold,sent_at FROM notifications LIMIT 0",
        "SELECT pem,archived,superseded_by FROM certificates LIMIT 0",
        "SELECT certificate_id,role,name,email FROM contacts LIMIT 0",
        "SELECT id,certificate_id,kind,recipient_name,recipient_email,threshold,"
        "subject,body,attachment_pem,status,attempts,last_error,created_at,"
        "sent_at,next_attempt FROM outbox LIMIT 0",
        "SELECT id,certificate_id,target,interval_seconds,enabled,revision,next_check_at,"
        "last_checked_at,last_status,last_error,last_fingerprint,last_address,dns_ok,"
        "tcp_ok,tls_ok,verified,claim_until,created_at,updated_at FROM monitors LIMIT 0",
        ("SELECT id,monitor_id,kind,message,expected_fingerprint,observed_fingerprint,"
        "created_at,acknowledged_at FROM monitor_events LIMIT 0"),
        "SELECT id,enabled,host,port,security,from_email,username,password_cipher,"
        "updated_at FROM smtp_settings LIMIT 0",
        "SELECT id,old_certificate_id,new_certificate_id,status,requested_at,planned_renewal_at,planned_install_at,responsible,notes,created_at,updated_at,finished_at FROM renewal_jobs LIMIT 0",
        "SELECT job_id,monitor_id,verify_requested_at,verified_at,last_match_at FROM renewal_endpoints LIMIT 0",
        "SELECT certificate_id,thresholds,escalation_email,escalation_name,escalation_after_days,enabled FROM reminder_policies LIMIT 0",
        "SELECT email_alerts FROM monitors LIMIT 0",
        "SELECT monitor_id,name,email FROM monitor_recipients LIMIT 0",
        "SELECT event_id FROM outbox LIMIT 0",
        "SELECT id,name,email FROM directory_people LIMIT 0",
        "SELECT id,name FROM directory_groups LIMIT 0",
        "SELECT group_id,person_id FROM directory_memberships LIMIT 0",
        "SELECT certificate_id,role,group_id FROM certificate_groups LIMIT 0",
        "SELECT certificate_id,role,person_id,group_id FROM directory_assignments LIMIT 0"
    };
    size_t i;

    size_t query_count = version >= 5 ? sizeof(queries) / sizeof(queries[0]) :
                         version >= 4 ? 8 :
                         version >= 3 ? 7 : version >= 2 ? 5 : 2;
    for (i = 0; i < query_count; ++i) {
        sqlite3_stmt *stmt = NULL;
        int rc;

        if (sqlite3_prepare_v2(store->db, queries[i], -1, &stmt,
                               NULL) != SQLITE_OK) {
            return db_error(store, err, errlen);
        }
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            (void)db_error(store, err, errlen);
            sqlite3_finalize(stmt);
            return 0;
        }
        rc = sqlite3_finalize(stmt);
        if (rc != SQLITE_OK) {
            return db_error(store, err, errlen);
        }
    }
    if (version >= 6) {
        const char *checks[]={
            "SELECT id,entity_type,entity_id,action,detail,created_at FROM workflow_audit LIMIT 0",
            "SELECT id,status,name_policy FROM inventory_batches LIMIT 0",
            "SELECT id,batch_id,payload,status,plan_json,review_token,keep_token,update_token,claim_until,lease_token FROM inventory_rows LIMIT 0",
            "SELECT idempotency_key,payload_hash,certificate_id FROM inventory_commits LIMIT 0",
            "SELECT id,name,thresholds,enabled,escalation_email,escalation_name,escalation_after_days FROM policy_templates LIMIT 0",
            "SELECT job_id,mode,captured_at,report_json FROM renewal_closure_reports LIMIT 0",
            "SELECT monitor_id,failure_threshold,consecutive_failures,incident_open,maintenance_start,maintenance_end,maintenance_processed,post_maintenance_check FROM monitor_options LIMIT 0",
            "SELECT event_id,responsible,notes,due_at,status FROM event_claims LIMIT 0"
        };
        for(size_t j=0;j<sizeof checks/sizeof checks[0];j++) {sqlite3_stmt *q=NULL;
            if(sqlite3_prepare_v2(store->db,checks[j],-1,&q,NULL)!=SQLITE_OK)return db_error(store,err,errlen);
            int ok=sqlite3_step(q)==SQLITE_DONE;sqlite3_finalize(q);if(!ok)return db_error(store,err,errlen);
        }
    }
    if (version >= 7) {
        const char *checks[] = {
            "SELECT id,self_name,self_email,updated_at FROM mail_template_settings LIMIT 0",
            "SELECT alert,audience,subject,body,copy_enabled,updated_at FROM mail_templates LIMIT 0",
            "SELECT template_alert,template_audience,template_copy FROM outbox LIMIT 0"
        };
        for (size_t j = 0; j < sizeof checks / sizeof checks[0]; j++) {
            sqlite3_stmt *stmt = NULL;
            if (sqlite3_prepare_v2(store->db, checks[j], -1, &stmt, NULL) != SQLITE_OK)
                return db_error(store, err, errlen);
            int ok = sqlite3_step(stmt) == SQLITE_DONE;
            sqlite3_finalize(stmt);
            if (!ok) return db_error(store, err, errlen);
        }
    }
    return 1;
}

int store_open(Store *store, const char *path, char *err, size_t errlen)
{
    static const char schema[] =
        "CREATE TABLE IF NOT EXISTS certificates ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "fingerprint TEXT NOT NULL UNIQUE,"
        "common_name TEXT NOT NULL,"
        "subject TEXT NOT NULL,"
        "issuer TEXT NOT NULL,"
        "serial TEXT NOT NULL,"
        "sans TEXT NOT NULL,"
        "key_algorithm TEXT NOT NULL,"
        "key_bits INTEGER NOT NULL,"
        "signature_algorithm TEXT NOT NULL,"
        "is_ca INTEGER NOT NULL,"
        "not_before INTEGER NOT NULL,"
        "not_after INTEGER NOT NULL,"
        "source TEXT NOT NULL,"
        "added_at INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS notifications ("
        "certificate_id INTEGER NOT NULL REFERENCES certificates(id) "
        "ON DELETE CASCADE,"
        "threshold INTEGER NOT NULL CHECK(threshold IN (45,30,15,2,0)),"
        "sent_at INTEGER NOT NULL,"
        "PRIMARY KEY(certificate_id,threshold)"
        ");";
    static const char migration_v2[] =
        "ALTER TABLE certificates ADD COLUMN pem TEXT NOT NULL DEFAULT '';"
        "ALTER TABLE certificates ADD COLUMN archived INTEGER NOT NULL DEFAULT 0 CHECK(archived IN(0,1));"
        "ALTER TABLE certificates ADD COLUMN superseded_by INTEGER REFERENCES certificates(id) ON DELETE SET NULL;"
        "CREATE TABLE contacts ("
        "certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,"
        "role TEXT NOT NULL CHECK(role IN('business','technical')),"
        "name TEXT NOT NULL DEFAULT '',email TEXT NOT NULL COLLATE NOCASE,"
        "PRIMARY KEY(certificate_id,role,email));"
        "CREATE TABLE outbox ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,"
        "kind TEXT NOT NULL CHECK(kind IN('expiry','certificate')),"
        "recipient_name TEXT NOT NULL,recipient_email TEXT NOT NULL,"
        "threshold INTEGER NOT NULL DEFAULT -1,subject TEXT NOT NULL,body TEXT NOT NULL,"
        "attachment_pem TEXT NOT NULL DEFAULT '',"
        "status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','sending','sent','failed')),"
        "attempts INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',"
        "created_at INTEGER NOT NULL,sent_at INTEGER,next_attempt INTEGER NOT NULL DEFAULT 0,"
        "UNIQUE(certificate_id,kind,recipient_email,threshold));";
    static const char migration_v3[] =
        "CREATE TABLE monitors ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,"
        "target TEXT NOT NULL,"
        "interval_seconds INTEGER NOT NULL DEFAULT 900 CHECK(interval_seconds BETWEEN 60 AND 86400),"
        "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN(0,1)),"
        "revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),"
        "next_check_at INTEGER NOT NULL DEFAULT 0,last_checked_at INTEGER,"
        "last_status TEXT NOT NULL DEFAULT 'pending' CHECK(last_status IN"
        "('pending','ok','unreachable','tls_error','changed','verification_error','error')),"
        "last_error TEXT NOT NULL DEFAULT '',last_fingerprint TEXT NOT NULL DEFAULT '',"
        "last_address TEXT NOT NULL DEFAULT '',dns_ok INTEGER NOT NULL DEFAULT 0,"
        "tcp_ok INTEGER NOT NULL DEFAULT 0,tls_ok INTEGER NOT NULL DEFAULT 0,"
        "verified INTEGER NOT NULL DEFAULT 0,claim_until INTEGER NOT NULL DEFAULT 0,"
        "created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,UNIQUE(certificate_id,target));"
        "CREATE INDEX monitors_due ON monitors(enabled,next_check_at,claim_until);"
        "CREATE TABLE monitor_events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,"
        "kind TEXT NOT NULL CHECK(kind IN"
        "('unreachable','tls_error','changed','verification_error','error','recovered')),"
        "message TEXT NOT NULL,expected_fingerprint TEXT NOT NULL,"
        "observed_fingerprint TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,acknowledged_at INTEGER);"
        "CREATE INDEX monitor_events_recent ON monitor_events(created_at,id);";
    static const char migration_v4[] =
        "CREATE TABLE smtp_settings ("
        "id INTEGER PRIMARY KEY CHECK(id=1),"
        "enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN(0,1)),"
        "host TEXT NOT NULL DEFAULT '',"
        "port INTEGER NOT NULL DEFAULT 587 CHECK(port BETWEEN 1 AND 65535),"
        "security TEXT NOT NULL DEFAULT 'starttls' CHECK(security IN('starttls','tls')),"
        "from_email TEXT NOT NULL DEFAULT '',username TEXT NOT NULL DEFAULT '',"
        "password_cipher BLOB,updated_at INTEGER NOT NULL);";
    static const char migration_v5[] =
        "CREATE TABLE renewal_jobs (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "old_certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,"
        "new_certificate_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL,"
        "status TEXT NOT NULL DEFAULT 'requested' CHECK(status IN('requested','awaiting_ca','signed','delivered','installing','verified','retired')),"
        "requested_at INTEGER NOT NULL DEFAULT 0,planned_renewal_at INTEGER,planned_install_at INTEGER,"
        "responsible TEXT NOT NULL DEFAULT '',notes TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,finished_at INTEGER,"
        "CHECK(new_certificate_id IS NULL OR new_certificate_id<>old_certificate_id),UNIQUE(old_certificate_id,new_certificate_id));"
        "CREATE TABLE renewal_endpoints (job_id INTEGER NOT NULL REFERENCES renewal_jobs(id) ON DELETE CASCADE,"
        "monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,verify_requested_at INTEGER,verified_at INTEGER,last_match_at INTEGER,PRIMARY KEY(job_id,monitor_id));"
        "CREATE TABLE reminder_policies (certificate_id INTEGER PRIMARY KEY REFERENCES certificates(id) ON DELETE CASCADE,"
        "thresholds TEXT NOT NULL DEFAULT '45,30,15,2,0',escalation_email TEXT NOT NULL DEFAULT '',escalation_name TEXT NOT NULL DEFAULT '',"
        "escalation_after_days INTEGER NOT NULL DEFAULT 7 CHECK(escalation_after_days BETWEEN 0 AND 365),enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN(0,1)));"
        ;
    static const char migration_v5_queue[] =
        "ALTER TABLE notifications RENAME TO notifications_v4;"
        "CREATE TABLE notifications(certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,"
        "threshold INTEGER NOT NULL CHECK(threshold BETWEEN 0 AND 3650),sent_at INTEGER NOT NULL,PRIMARY KEY(certificate_id,threshold));"
        "INSERT INTO notifications SELECT * FROM notifications_v4;DROP TABLE notifications_v4;"
        "ALTER TABLE monitors ADD COLUMN email_alerts INTEGER NOT NULL DEFAULT 0 CHECK(email_alerts IN(0,1));"
        "CREATE TABLE monitor_recipients(monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,name TEXT NOT NULL DEFAULT '',"
        "email TEXT NOT NULL COLLATE NOCASE,PRIMARY KEY(monitor_id,email));"
        "ALTER TABLE outbox RENAME TO outbox_v4;"
        "CREATE TABLE outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,"
        "kind TEXT NOT NULL CHECK(kind IN('expiry','certificate','escalation','monitor')),recipient_name TEXT NOT NULL,recipient_email TEXT NOT NULL,"
        "threshold INTEGER NOT NULL DEFAULT -1,subject TEXT NOT NULL,body TEXT NOT NULL,attachment_pem TEXT NOT NULL DEFAULT '',"
        "status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','sending','sent','failed')),attempts INTEGER NOT NULL DEFAULT 0,"
        "last_error TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,sent_at INTEGER,next_attempt INTEGER NOT NULL DEFAULT 0,"
        "event_id INTEGER REFERENCES monitor_events(id) ON DELETE CASCADE);"
        "INSERT INTO outbox(id,certificate_id,kind,recipient_name,recipient_email,threshold,subject,body,attachment_pem,status,attempts,last_error,created_at,sent_at,next_attempt) "
        "SELECT id,certificate_id,kind,recipient_name,recipient_email,threshold,subject,body,attachment_pem,status,attempts,last_error,created_at,sent_at,next_attempt FROM outbox_v4;"
        "DROP TABLE outbox_v4;"
        "CREATE UNIQUE INDEX outbox_certificate_unique ON outbox(certificate_id,kind,recipient_email,threshold) WHERE kind<>'monitor';"
        "CREATE UNIQUE INDEX outbox_monitor_unique ON outbox(event_id,recipient_email) WHERE kind='monitor';"
        ;
    static const char migration_v5_directory[] =
        "CREATE TABLE directory_people(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL DEFAULT '',email TEXT NOT NULL UNIQUE COLLATE NOCASE);"
        "CREATE TABLE directory_groups(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL UNIQUE COLLATE NOCASE);"
        "CREATE TABLE directory_memberships(group_id INTEGER NOT NULL REFERENCES directory_groups(id) ON DELETE CASCADE,person_id INTEGER NOT NULL REFERENCES directory_people(id) ON DELETE CASCADE,PRIMARY KEY(group_id,person_id));"
        "CREATE TABLE certificate_groups(certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,role TEXT NOT NULL CHECK(role IN('business','technical')),group_id INTEGER NOT NULL REFERENCES directory_groups(id) ON DELETE CASCADE,PRIMARY KEY(certificate_id,role,group_id));"
        "CREATE TABLE directory_assignments(certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,role TEXT NOT NULL CHECK(role IN('business','technical')),person_id INTEGER NOT NULL REFERENCES directory_people(id) ON DELETE CASCADE,group_id INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(certificate_id,role,person_id,group_id));"
        "INSERT OR IGNORE INTO directory_people(name,email) SELECT name,email FROM contacts ORDER BY certificate_id,role;"
        "INSERT OR IGNORE INTO directory_assignments(certificate_id,role,person_id,group_id) SELECT c.certificate_id,c.role,p.id,0 FROM contacts c JOIN directory_people p ON p.email=c.email COLLATE NOCASE;"
        "INSERT OR IGNORE INTO renewal_jobs(old_certificate_id,new_certificate_id,status,requested_at,notes,created_at,updated_at,finished_at) "
        "SELECT id,superseded_by,'retired',added_at,'Storico importato dalla versione precedente; installazione non verificata.',added_at,added_at,added_at FROM certificates WHERE archived=1 AND superseded_by IS NOT NULL;";
    int version;
    int rc;

    set_error(err, errlen, "");
    if (store == NULL) {
        set_error(err, errlen, "Database non valido.");
        return 0;
    }
    store->db = NULL;
    OPENSSL_cleanse(store->smtp_key, sizeof store->smtp_key);
    store->smtp_key_loaded = 0;
    if (path == NULL || path[0] == '\0') {
        set_error(err, errlen, "Percorso del database mancante.");
        return 0;
    }

#ifndef _WIN32
    /* Never change the permissions of an existing database. */
    if (strcmp(path, ":memory:") != 0) {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) {
            if (close(fd) != 0) {
                set_error(err, errlen, strerror(errno));
                return 0;
            }
        } else if (errno != EEXIST) {
            set_error(err, errlen, strerror(errno));
            return 0;
        }
    }
#endif

    rc = sqlite3_open_v2(path, &store->db,
                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) {
        if (store->db != NULL) {
            (void)db_error(store, err, errlen);
        } else {
            set_error(err, errlen, "Impossibile aprire il database.");
        }
        store_close(store);
        return 0;
    }
    (void)sqlite3_extended_result_codes(store->db, 1);
    if (sqlite3_busy_timeout(store->db, 5000) != SQLITE_OK ||
        !store_exec(store, "PRAGMA foreign_keys=ON", err, errlen) ||
        !schema_version(store, &version, err, errlen)) {
        if (err != NULL && errlen > 0 && err[0] == '\0') {
            (void)db_error(store, err, errlen);
        }
        store_close(store);
        return 0;
    }
    if (version < 0 || version > STORE_SCHEMA_VERSION) {
        if (err != NULL && errlen > 0) {
            (void)snprintf(err, errlen,
                           "Versione database %d non supportata (attesa %d).",
                           version, STORE_SCHEMA_VERSION);
        }
        store_close(store);
        return 0;
    }
    if (version < STORE_SCHEMA_VERSION) {
        if (!store_exec(store, "BEGIN IMMEDIATE", err, errlen)) {
            store_close(store);
            return 0;
        }
        int ok = schema_version(store, &version, err, errlen);
        if (ok && version == 0) {
            ok = store_exec(store, schema, err, errlen) &&
                 validate_schema(store, 1, err, errlen) &&
                 store_exec(store, "PRAGMA user_version=1", err, errlen);
            version = 1;
        }
        if (ok && version == 1) {
            ok = validate_schema(store, 1, err, errlen) &&
                 store_exec(store, migration_v2, err, errlen) &&
                 validate_schema(store, 2, err, errlen) &&
                 store_exec(store, "PRAGMA user_version=2", err, errlen);
            version = 2;
        }
        if (ok && version == 2) {
            ok = validate_schema(store, 2, err, errlen) &&
                 store_exec(store, migration_v3, err, errlen) &&
                 validate_schema(store, 3, err, errlen) &&
                 store_exec(store, "PRAGMA user_version=3", err, errlen);
            version = 3;
        }
        if (ok && version == 3) {
            ok = validate_schema(store, 3, err, errlen) &&
                 store_exec(store, migration_v4, err, errlen) &&
                 validate_schema(store, 4, err, errlen) &&
                 store_exec(store, "PRAGMA user_version=4", err, errlen);
            version = 4;
        }
        if (ok && version == 4) {
            ok = validate_schema(store, 4, err, errlen) &&
                 store_exec(store, migration_v5, err, errlen) &&
                 store_exec(store, migration_v5_queue, err, errlen) &&
                 store_exec(store, migration_v5_directory, err, errlen) &&
                 validate_schema(store, 5, err, errlen) &&
                 store_exec(store, "PRAGMA user_version=5", err, errlen);
            version = 5;
        }
        if (ok && version == 5) {
            ok = validate_schema(store, 5, err, errlen) &&
                 store_exec(store, wf_schema(), err, errlen) &&
                 store_exec(store, inventory_schema(), err, errlen) &&
                 store_exec(store, operations_schema(), err, errlen) &&
                 store_exec(store, incident_schema(), err, errlen) &&
                 store_exec(store, "PRAGMA user_version=6", err, errlen);
            version = 6;
        }
        if (ok && version == 6) {
            ok = validate_schema(store, 6, err, errlen) &&
                 store_exec(store, mail_templates_schema(), err, errlen) &&
                 store_exec(store, "PRAGMA user_version=7", err, errlen);
            version = 7;
        }
        if (ok) ok = version == STORE_SCHEMA_VERSION &&
                     validate_schema(store, STORE_SCHEMA_VERSION, err, errlen) &&
                     store_exec(store, "COMMIT", err, errlen);
        if (!ok) {
            (void)store_exec(store, "ROLLBACK", NULL, 0);
            store_close(store);
            return 0;
        }
    } else if (!validate_schema(store, STORE_SCHEMA_VERSION, err, errlen)) {
        store_close(store);
        return 0;
    }
    return 1;
}

void store_close(Store *store)
{
    if (store != NULL && store->db != NULL) {
        (void)sqlite3_close_v2(store->db);
        store->db = NULL;
    }
    if (store != NULL) {
        OPENSSL_cleanse(store->smtp_key, sizeof store->smtp_key);
        store->smtp_key_loaded = 0;
    }
}

static int bind_text(sqlite3_stmt *stmt, int index, const char *value)
{
    return sqlite3_bind_text(stmt, index, value != NULL ? value : "", -1,
                              SQLITE_TRANSIENT) == SQLITE_OK;
}

int store_add(Store *store, const Certificate *cert, const char *source,
              int64_t now, int64_t *id, int *inserted, char *err,
              size_t errlen)
{
    static const char insert_sql[] =
        "INSERT INTO certificates "
        "(fingerprint,common_name,subject,issuer,serial,sans,key_algorithm,"
        "key_bits,signature_algorithm,is_ca,not_before,not_after,source,added_at,pem)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(fingerprint) DO NOTHING";
    sqlite3_stmt *stmt = NULL;
    int rc;
    int was_inserted;
    int64_t record_id;

    if (id != NULL) {
        *id = 0;
    }
    if (inserted != NULL) {
        *inserted = 0;
    }
    if (store == NULL || store->db == NULL || cert == NULL ||
        cert->fingerprint == NULL || cert->fingerprint[0] == '\0') {
        set_error(err, errlen, "Certificato o database non valido.");
        return 0;
    }
    if (sqlite3_prepare_v2(store->db, insert_sql, -1, &stmt,
                           NULL) != SQLITE_OK) {
        return db_error(store, err, errlen);
    }
    if (!bind_text(stmt, 1, cert->fingerprint) ||
        !bind_text(stmt, 2, cert->common_name) ||
        !bind_text(stmt, 3, cert->subject) ||
        !bind_text(stmt, 4, cert->issuer) ||
        !bind_text(stmt, 5, cert->serial) ||
        !bind_text(stmt, 6, cert->sans) ||
        !bind_text(stmt, 7, cert->key_algorithm) ||
        sqlite3_bind_int(stmt, 8, cert->key_bits) != SQLITE_OK ||
        !bind_text(stmt, 9, cert->signature_algorithm) ||
        sqlite3_bind_int(stmt, 10, cert->is_ca) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 11, cert->not_before) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 12, cert->not_after) != SQLITE_OK ||
        !bind_text(stmt, 13, source) ||
        sqlite3_bind_int64(stmt, 14, now) != SQLITE_OK ||
        !bind_text(stmt, 15, cert->pem)) {
        (void)db_error(store, err, errlen);
        sqlite3_finalize(stmt);
        return 0;
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        (void)db_error(store, err, errlen);
        sqlite3_finalize(stmt);
        return 0;
    }
    was_inserted = sqlite3_changes(store->db) != 0;
    record_id = sqlite3_last_insert_rowid(store->db);
    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        return db_error(store, err, errlen);
    }

    if (!was_inserted) {
        static const char update_sql[] =
            "UPDATE certificates SET source=?,pem=CASE WHEN pem='' AND ?<>'' THEN ? ELSE pem END "
            "WHERE fingerprint=?";
        static const char select_sql[] =
            "SELECT id FROM certificates WHERE fingerprint=?";

        stmt = NULL;
        if (sqlite3_prepare_v2(store->db, update_sql, -1, &stmt,
                               NULL) != SQLITE_OK) {
            return db_error(store, err, errlen);
        }
        if (!bind_text(stmt, 1, source) || !bind_text(stmt, 2, cert->pem) ||
            !bind_text(stmt, 3, cert->pem) || !bind_text(stmt, 4, cert->fingerprint)) {
            (void)db_error(store, err, errlen);
            sqlite3_finalize(stmt);
            return 0;
        }
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            (void)db_error(store, err, errlen);
            sqlite3_finalize(stmt);
            return 0;
        }
        rc = sqlite3_finalize(stmt);
        if (rc != SQLITE_OK) {
            return db_error(store, err, errlen);
        }
        stmt = NULL;
        if (sqlite3_prepare_v2(store->db, select_sql, -1, &stmt,
                               NULL) != SQLITE_OK) {
            return db_error(store, err, errlen);
        }
        if (!bind_text(stmt, 1, cert->fingerprint)) {
            (void)db_error(store, err, errlen);
            sqlite3_finalize(stmt);
            return 0;
        }
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW) {
            if (rc == SQLITE_DONE) {
                set_error(err, errlen,
                          "Certificato rimosso durante l'aggiornamento.");
            } else {
                (void)db_error(store, err, errlen);
            }
            sqlite3_finalize(stmt);
            return 0;
        }
        record_id = sqlite3_column_int64(stmt, 0);
        rc = sqlite3_finalize(stmt);
        if (rc != SQLITE_OK) {
            return db_error(store, err, errlen);
        }
    }
    if (id != NULL) {
        *id = record_id;
    }
    if (inserted != NULL) {
        *inserted = was_inserted;
    }
    return 1;
}

int store_remove(Store *store, int64_t id, int *removed, char *err,
                 size_t errlen)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    int changed;

    if (removed != NULL) {
        *removed = 0;
    }
    if (store == NULL || store->db == NULL) {
        set_error(err, errlen, "Database non aperto.");
        return 0;
    }
    if (sqlite3_prepare_v2(store->db, "DELETE FROM certificates WHERE id=?",
                           -1, &stmt, NULL) != SQLITE_OK) {
        return db_error(store, err, errlen);
    }
    if (sqlite3_bind_int64(stmt, 1, id) != SQLITE_OK) {
        (void)db_error(store, err, errlen);
        sqlite3_finalize(stmt);
        return 0;
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        (void)db_error(store, err, errlen);
        sqlite3_finalize(stmt);
        return 0;
    }
    changed = sqlite3_changes(store->db) != 0;
    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        return db_error(store, err, errlen);
    }
    if (removed != NULL) {
        *removed = changed;
    }
    return 1;
}

static int ascii_letter_or_digit(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

int store_email_valid(const char *email)
{
    const char *at;
    const char *label;
    size_t length;
    if (email == NULL || (length = strlen(email)) == 0 || length > 254)
        return 0;
    at = strchr(email, '@');
    if (at == NULL || at == email || (size_t)(at - email) > 64 || at[1] == '\0' ||
        strchr(at + 1, '@') != NULL || email[0] == '.' || at[-1] == '.')
        return 0;
    for (const char *p = email; p < at; ++p) {
        unsigned char c = (unsigned char)*p;
        if (!ascii_letter_or_digit(c) && c != '.' && c != '_' && c != '%' &&
            c != '+' && c != '-')
            return 0;
        if (c == '.' && p + 1 < at && p[1] == '.')
            return 0;
    }
    label = at + 1;
    for (const char *p = label;; ++p) {
        unsigned char c = (unsigned char)*p;
        if (c == '.' || c == '\0') {
            size_t label_length = (size_t)(p - label);
            if (label_length == 0 || label_length > 63 || label[0] == '-' || p[-1] == '-')
                return 0;
            if (c == '\0')
                break;
            label = p + 1;
        } else if (!ascii_letter_or_digit(c) && c != '-') {
            return 0;
        }
    }
    return 1;
}

static int ascii_equal_insensitive(const char *a, const char *b)
{
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a++;
        unsigned char cb = (unsigned char)*b++;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + ('a' - 'A'));
        if (ca != cb) return 0;
    }
    return *a == *b;
}

int store_set_contacts(Store *store, int64_t id, const StoreContact *contacts,
                       size_t count, char *err, size_t errlen)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    set_error(err, errlen, "");
    if (store == NULL || store->db == NULL || id <= 0 || count > 100 ||
        (count != 0 && contacts == NULL)) {
        set_error(err, errlen, "Certificato o elenco contatti non valido (massimo 100 contatti).");
        return 0;
    }
    for (size_t i = 0; i < count; ++i) {
        const StoreContact *contact = &contacts[i];
        const char *name = contact->name != NULL ? contact->name : "";
        if (contact->role == NULL ||
            (strcmp(contact->role, "business") != 0 && strcmp(contact->role, "technical") != 0) ||
            strlen(name) > 120 || !store_email_valid(contact->email)) {
            set_error(err, errlen, "Contatto non valido: ruolo, nome (massimo 120 byte) o indirizzo email.");
            return 0;
        }
        for (const unsigned char *p = (const unsigned char *)name; *p; ++p) {
            if (*p < 32 || *p == 127) {
                set_error(err, errlen, "Il nome del contatto contiene caratteri di controllo.");
                return 0;
            }
        }
        for (size_t j = 0; j < i; ++j) {
            if (strcmp(contact->role, contacts[j].role) == 0 &&
                ascii_equal_insensitive(contact->email, contacts[j].email)) {
                set_error(err, errlen, "Indirizzo email duplicato per lo stesso ruolo.");
                return 0;
            }
        }
    }
    if (!store_exec(store, "SAVEPOINT store_contacts", err, errlen))
        return 0;
    if (sqlite3_prepare_v2(store->db, "SELECT 1 FROM certificates WHERE id=?", -1,
                           &stmt, NULL) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 1, id) != SQLITE_OK)
        goto database_failure;
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (rc != SQLITE_ROW) {
        if (rc == SQLITE_DONE)
            set_error(err, errlen, "Certificato non trovato.");
        else
            (void)db_error(store, err, errlen);
        goto failure;
    }
    if (sqlite3_prepare_v2(store->db, "DELETE FROM contacts WHERE certificate_id=?", -1,
                           &stmt, NULL) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 1, id) != SQLITE_OK ||
        sqlite3_step(stmt) != SQLITE_DONE)
        goto database_failure;
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (count != 0 && sqlite3_prepare_v2(store->db,
        "INSERT INTO contacts(certificate_id,role,name,email) VALUES(?,?,?,?)", -1,
        &stmt, NULL) != SQLITE_OK)
        goto database_failure;
    for (size_t i = 0; i < count; ++i) {
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
        if (sqlite3_bind_int64(stmt, 1, id) != SQLITE_OK ||
            !bind_text(stmt, 2, contacts[i].role) ||
            !bind_text(stmt, 3, contacts[i].name) ||
            !bind_text(stmt, 4, contacts[i].email) || sqlite3_step(stmt) != SQLITE_DONE)
            goto database_failure;
    }
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (store_exec(store, "RELEASE store_contacts", err, errlen))
        return 1;
    goto failure;
database_failure:
    (void)db_error(store, err, errlen);
failure:
    sqlite3_finalize(stmt);
    (void)store_exec(store, "ROLLBACK TO store_contacts", NULL, 0);
    (void)store_exec(store, "RELEASE store_contacts", NULL, 0);
    return 0;
}
