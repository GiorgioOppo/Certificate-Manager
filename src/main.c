#define _POSIX_C_SOURCE 200809L
#include "app.h"
#include "delivery.h"
#include "monitor.h"
#include "inventory.h"
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void stop_app(int sig) {
    (void)sig;
    app_running = 0;
}

static void usage(void) {
    puts("Gestione certificati HTTPS\n"
         "Uso: certificati [--db ARCHIVIO] [comando]\n\n"
         "  serve [--bind IP] [--port PORTA]\n"
         "                            Interfaccia web (predefinito: 127.0.0.1:8080)\n"
         "  import FILE...            Importa certificati PEM, bundle PEM o DER\n"
         "  list                      Tabella delle scadenze\n"
         "  show ID                   Dettagli di un certificato\n"
         "  remove ID                 Elimina certificato e relativi promemoria\n"
         "  check                     Controlla subito le soglie 45, 30, 15, 2 giorni\n"
         "  watch [--interval SEC]    Controllo continuo (predefinito: 60 secondi)\n"
         "  help                      Mostra questa guida\n\n"
         "Indirizzi di ascolto: 127.0.0.1 (locale), 0.0.0.0 (tutte le interfacce IPv4).\n"
         "In Docker pubblicare la porta solo su 127.0.0.1, mantenendo la stessa porta interna.\n"
         "Archivio predefinito: certificati.db nella cartella corrente.\n"
         "Il server deve restare acceso per generare i promemoria automatici.");
}

static int64_t positive_integer(const char *s, int64_t max) {
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++) if (*p < '0' || *p > '9') return 0;
    errno = 0;
    char *end = NULL;
    long long value = strtoll(s, &end, 10);
    return !errno && !*end && value > 0 && value <= max ? (int64_t)value : 0;
}

static void date_text(int64_t epoch, char text[32]) {
    time_t value = (time_t)epoch;
    struct tm utc;
    if (!gmtime_r(&value, &utc) || !strftime(text, 32, "%Y-%m-%d %H:%M UTC", &utc))
        strcpy(text, "data non disponibile");
}

static int show_list(Store *s, int64_t id) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = id ? "SELECT * FROM certificates WHERE id=?1" :
                          "SELECT * FROM certificates WHERE archived=0 ORDER BY not_after,id";
    if (sqlite3_prepare_v2(s->db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    if (id) sqlite3_bind_int64(stmt, 1, id);
    int rc, found = 0;
    if (!id) printf("%-5s %-32s %-24s %-22s %-8s %s\n", "ID", "DOMINIO / CN", "EMITTENTE", "SCADENZA", "GIORNI", "STATO");
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        found++;
        int64_t start = 0, expiry = 0, row_id = 0;
        const char *cn = "", *issuer = "";
        for (int i = 0; i < sqlite3_column_count(stmt); i++) {
            const char *name = sqlite3_column_name(stmt, i);
            if (!strcmp(name, "id")) row_id = sqlite3_column_int64(stmt, i);
            if (!strcmp(name, "common_name")) cn = (const char *)sqlite3_column_text(stmt, i);
            if (!strcmp(name, "issuer")) issuer = (const char *)sqlite3_column_text(stmt, i);
            if (!strcmp(name, "not_before")) start = sqlite3_column_int64(stmt, i);
            if (!strcmp(name, "not_after")) expiry = sqlite3_column_int64(stmt, i);
            if (id) {
                if (!strcmp(name, "pem")) continue;
                printf("%-22s ", name);
                if (!strcmp(name, "not_before") || !strcmp(name, "not_after") || !strcmp(name, "added_at")) {
                    char date[32]; date_text(sqlite3_column_int64(stmt, i), date); puts(date);
                } else if (sqlite3_column_type(stmt, i) == SQLITE_INTEGER)
                    printf("%" PRId64 "\n", (int64_t)sqlite3_column_int64(stmt, i));
                else {
                    const char *text = (const char *)sqlite3_column_text(stmt, i);
                    puts(text ? text : "—");
                }
            }
        }
        int64_t now = (int64_t)time(NULL);
        if (!id) {
            char date[32]; date_text(expiry, date);
            printf("%-5" PRId64 " %-32.32s %-24.24s %-22s %-8" PRId64 " %s\n",
                   row_id, cn, issuer, date, app_days_remaining(expiry, now),
                   app_status(start, expiry, now));
        }
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return 0;
    if (!found) puts(id ? "Certificato non trovato." : "Nessun certificato. Importa un file dal browser o con il comando import.");
    return id && !found ? 0 : 1;
}

int main(int argc, char **argv) {
    const char *db_path = "certificati.db";
    int arg = 1;
    if (arg < argc && !strcmp(argv[arg], "--db")) {
        if (++arg == argc) { usage(); return 2; }
        db_path = argv[arg++];
    }
    const char *cmd = arg < argc ? argv[arg++] : "serve";
    if (!strcmp(cmd, "help") || !strcmp(cmd, "--help") || !strcmp(cmd, "-h")) {
        usage(); return 0;
    }
    int serving = !strcmp(cmd, "serve"), watching = !strcmp(cmd, "watch");
    int importing = !strcmp(cmd, "import"), listing = !strcmp(cmd, "list");
    int showing = !strcmp(cmd, "show"), removing = !strcmp(cmd, "remove"), checking = !strcmp(cmd, "check");
    int64_t parameter = serving ? 8080 : 60;
    const char *bind_address = "127.0.0.1";
    if (serving) {
        int port_seen = 0, bind_seen = 0;
        while (arg < argc) {
            if (argc - arg < 2) { usage(); return 2; }
            if (!strcmp(argv[arg], "--port") && !port_seen) {
                port_seen = 1;
                if (!(parameter = positive_integer(argv[arg + 1], 65535))) { usage(); return 2; }
            } else if (!strcmp(argv[arg], "--bind") && !bind_seen) {
                bind_seen = 1;
                bind_address = argv[arg + 1];
                if (strcmp(bind_address, "127.0.0.1") && strcmp(bind_address, "0.0.0.0")) {
                    usage(); return 2;
                }
            } else { usage(); return 2; }
            arg += 2;
        }
    } else if (watching) {
        if (arg < argc) {
            if (argc - arg != 2 || strcmp(argv[arg], "--interval") ||
                !(parameter = positive_integer(argv[arg + 1], 86400))) {
                usage(); return 2;
            }
            arg += 2;
        }
    } else if (showing || removing) {
        if (argc - arg != 1 || !(parameter = positive_integer(argv[arg], INT64_MAX))) {
            usage(); return 2;
        }
        arg++;
    } else if (importing) {
        if (arg == argc) { usage(); return 2; }
    } else if ((!listing && !checking) || arg != argc) {
        usage(); return 2;
    }
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = stop_app;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    signal(SIGPIPE, SIG_IGN);
    Store store = {0};
    char error[512] = "";
    if (!store_open(&store, db_path, error, sizeof error)) {
        fprintf(stderr, "%s\n", error); return 1;
    }
    int ok = 1;
    if (serving) ok = app_serve(&store, bind_address, (unsigned short)parameter);
    else if (importing) {
        while (arg < argc) {
            int added, duplicates;
            if (!app_import(&store, argv[arg], argv[arg], &added, &duplicates, error, sizeof error)) {
                fprintf(stderr, "%s: %s\n", argv[arg], error); ok = 0;
            } else printf("%s: %d importati, %d già presenti.\n", argv[arg], added, duplicates);
            arg++;
        }
        if (ok) ok = show_list(&store, 0);
    } else if (listing || showing) ok = show_list(&store, showing ? parameter : 0);
    else if (removing) {
        int removed = 0;
        ok = store_remove(&store, parameter, &removed, error, sizeof error);
        if (ok) { puts(removed ? "Certificato eliminato." : "Certificato non trovato."); ok = removed; }
    } else {
        int64_t next_expiry_check = 0;
        do {
            int64_t now = (int64_t)time(NULL);
            if (now >= next_expiry_check) {
                int count = 0;
                ok = app_check(&store, now, &count, stdout, error, sizeof error);
                if (!ok) break;
                int sent = 0;
                ok = delivery_process(&store, now, &sent, error, sizeof error);
                if (!ok) break;
                if (!watching) printf("Controllo completato: %d nuovi promemoria.\n", count);
                next_expiry_check = now + parameter;
            }
            if (watching) {
                char monitor_error[512] = "";
                if (!inventory_tick(&store, now, monitor_error, sizeof monitor_error))
                    fprintf(stderr, "Inventario: %s\n", monitor_error);
                if (!monitor_tick(&store, now, monitor_error, sizeof monitor_error))
                    fprintf(stderr, "Monitoraggio URL: %s\n", monitor_error);
                struct timespec rest = { 1, 0 };
                while (app_running && nanosleep(&rest, &rest) && errno == EINTR) {}
            }
        } while (watching && app_running);
    }
    if (!ok && error[0]) fprintf(stderr, "%s\n", error);
    monitor_shutdown();
    inventory_shutdown();
    store_close(&store);
    return ok ? 0 : 1;
}
