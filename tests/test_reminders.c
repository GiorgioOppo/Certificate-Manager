#include "app.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DAY INT64_C(86400)
#define REQUIRE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: verifica fallita: %s\n", \
                __FILE__, __LINE__, #condition); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static char error[512];

static void open_store(Store *store)
{
    REQUIRE(store_open(store, ":memory:", error, sizeof error));
}

static int scalar(Store *store, const char *sql)
{
    sqlite3_stmt *query = NULL;
    REQUIRE(sqlite3_prepare_v2(store->db, sql, -1, &query, NULL) == SQLITE_OK);
    REQUIRE(sqlite3_step(query) == SQLITE_ROW);
    int result = sqlite3_column_int(query, 0);
    REQUIRE(sqlite3_finalize(query) == SQLITE_OK);
    return result;
}

static int64_t add_certificate(Store *store, char *fingerprint, int64_t expiry)
{
    Certificate cert = {
        .common_name = "test.example", .subject = "CN=test.example",
        .issuer = "CN=Test CA", .serial = "0123", .sans = "DNS:test.example",
        .fingerprint = fingerprint, .key_algorithm = "RSA", .key_bits = 2048,
        .signature_algorithm = "sha256WithRSAEncryption", .is_ca = 0,
        .not_before = expiry - 365 * DAY, .not_after = expiry
    };
    int64_t id = 0;
    int inserted = 0;
    REQUIRE(store_add(store, &cert, "test.pem", expiry - 100 * DAY,
                      &id, &inserted, error, sizeof error));
    REQUIRE(inserted && id > 0);
    return id;
}

static void check_count(Store *store, int64_t now, int expected)
{
    int count = -1;
    if (!app_check(store, now, &count, NULL, error, sizeof error)) {
        fprintf(stderr, "app_check: %s\n", error);
        exit(EXIT_FAILURE);
    }
    REQUIRE(count == expected);
}

static void test_days_and_status(void)
{
    int64_t now = INT64_C(2000000000);
    REQUIRE(app_days_remaining(now + 1, now) == 1);
    REQUIRE(app_days_remaining(now + DAY, now) == 1);
    REQUIRE(app_days_remaining(now + DAY + 1, now) == 2);
    REQUIRE(app_days_remaining(now, now) == 0);
    REQUIRE(app_days_remaining(now - 1, now) == -1);
    REQUIRE(app_days_remaining(now - DAY, now) == -1);
    REQUIRE(app_days_remaining(now - DAY - 1, now) == -2);
    REQUIRE(strcmp(app_status(now - DAY, now + 46 * DAY, now), "healthy") == 0);
    REQUIRE(strcmp(app_status(now - DAY, now + 45 * DAY, now), "warning") == 0);
    REQUIRE(strcmp(app_status(now - DAY, now + 2 * DAY, now), "urgent") == 0);
    REQUIRE(strcmp(app_status(now - DAY, now, now), "expired") == 0);
    REQUIRE(strcmp(app_status(now + 1, now + DAY, now), "not_yet_valid") == 0);
}

static void test_boundaries_and_duplicates(void)
{
    Store store;
    int64_t expiry = INT64_C(2100000000);
    const int thresholds[] = {45, 30, 15, 2, 0};
    open_store(&store);
    add_certificate(&store, "boundary-fingerprint", expiry);
    check_count(&store, expiry - 46 * DAY, 0);
    for (size_t i = 0; i < sizeof thresholds / sizeof thresholds[0]; ++i) {
        int64_t boundary = expiry - thresholds[i] * DAY;
        check_count(&store, boundary - 1, 0);
        check_count(&store, boundary, 1);
        check_count(&store, boundary, 0);
        REQUIRE(scalar(&store, "SELECT count(*) FROM notifications") == (int)i + 1);
    }
    check_count(&store, expiry + 100 * DAY, 0);
    REQUIRE(scalar(&store, "SELECT count(*) FROM notifications WHERE threshold=0") == 1);
    store_close(&store);
}

static void test_missed_checks_and_backward_clock(void)
{
    Store store;
    int64_t expiry = INT64_C(2100000000);
    open_store(&store);
    add_certificate(&store, "jump-fingerprint", expiry);
    check_count(&store, expiry - 20 * DAY, 1);
    REQUIRE(scalar(&store, "SELECT threshold FROM notifications") == 30);
    check_count(&store, expiry - 3 * DAY, 1);
    check_count(&store, expiry - DAY, 1);
    /* Older, less urgent thresholds must stay suppressed if the clock retreats. */
    check_count(&store, expiry - 40 * DAY, 0);
    check_count(&store, expiry - 20 * DAY, 0);
    check_count(&store, expiry, 1);
    REQUIRE(scalar(&store, "SELECT count(*) FROM notifications") == 4);
    REQUIRE(scalar(&store, "SELECT count(*) FROM notifications WHERE threshold=45") == 0);
    check_count(&store, expiry + 1, 0);
    store_close(&store);

    /* A certificate first discovered after expiration produces only threshold 0. */
    open_store(&store);
    add_certificate(&store, "expired-fingerprint", expiry);
    check_count(&store, expiry + DAY, 1);
    REQUIRE(scalar(&store, "SELECT threshold FROM notifications") == 0);
    check_count(&store, expiry - 45 * DAY, 0);
    store_close(&store);
}

static void test_reimport_and_cascade(void)
{
    Store store;
    int64_t expiry = INT64_C(2100000000);
    open_store(&store);
    int64_t original_id = add_certificate(&store, "duplicate-fingerprint", expiry);
    check_count(&store, expiry - 10 * DAY, 1);
    Certificate cert = {
        .common_name = "test.example", .subject = "CN=test.example",
        .issuer = "CN=Test CA", .serial = "0123", .sans = "DNS:test.example",
        .fingerprint = "duplicate-fingerprint", .key_algorithm = "RSA",
        .key_bits = 2048, .signature_algorithm = "sha256WithRSAEncryption",
        .not_before = expiry - 365 * DAY, .not_after = expiry
    };
    int inserted = -1, removed = -1;
    int64_t id = 0;
    REQUIRE(store_add(&store, &cert, "nome con ' apostrofo.pem", expiry - DAY,
                      &id, &inserted, error, sizeof error));
    REQUIRE(!inserted && id == original_id);
    REQUIRE(scalar(&store, "SELECT count(*) FROM certificates") == 1);
    REQUIRE(scalar(&store, "SELECT count(*) FROM notifications") == 1);
    REQUIRE(scalar(&store, "SELECT source='nome con '' apostrofo.pem' FROM certificates") == 1);
    check_count(&store, expiry - 10 * DAY, 0);
    REQUIRE(store_remove(&store, id, &removed, error, sizeof error) && removed);
    REQUIRE(scalar(&store, "SELECT count(*) FROM notifications") == 0);
    REQUIRE(store_remove(&store, id, &removed, error, sizeof error) && !removed);
    store_close(&store);
}

static void test_transaction_rollback(void)
{
    Store store;
    int64_t now = INT64_C(2100000000);
    int count = -1;
    open_store(&store);
    REQUIRE(add_certificate(&store, "first-fingerprint", now + DAY) == 1);
    REQUIRE(add_certificate(&store, "second-fingerprint", now + DAY) == 2);
    REQUIRE(store_exec(&store,
        "CREATE TRIGGER fail_second BEFORE INSERT ON notifications "
        "WHEN NEW.certificate_id=2 BEGIN SELECT RAISE(ABORT,'test rollback'); END",
        error, sizeof error));
    FILE *log = tmpfile();
    REQUIRE(log != NULL);
    REQUIRE(!app_check(&store, now, &count, log, error, sizeof error));
    REQUIRE(count == 0);
    REQUIRE(scalar(&store, "SELECT count(*) FROM notifications") == 0);
    REQUIRE(ftell(log) == 0);
    REQUIRE(store_exec(&store, "DROP TRIGGER fail_second", error, sizeof error));
    REQUIRE(app_check(&store, now, &count, log, error, sizeof error));
    REQUIRE(count == 2 && ftell(log) > 0);
    REQUIRE(fclose(log) == 0);
    check_count(&store, now, 0);
    store_close(&store);
}

int main(void)
{
    test_days_and_status();
    test_boundaries_and_duplicates();
    test_missed_checks_and_backward_clock();
    test_reimport_and_cascade();
    test_transaction_rollback();
    puts("Test promemoria: OK");
    return EXIT_SUCCESS;
}
