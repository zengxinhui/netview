#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "db.h"

static sqlite3_stmt *insert_stmt = NULL;

int db_init(const char *db_path, sqlite3 **db_out) {
    sqlite3 *db;
    int rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    // Enable WAL mode for high concurrency/throughput
    char *err_msg = NULL;
    rc = sqlite3_exec(db, "PRAGMA journal_mode = WAL;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to set WAL mode: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return -1;
    }

    // Set synchronous to NORMAL (safe for WAL, faster than FULL)
    rc = sqlite3_exec(db, "PRAGMA synchronous = NORMAL;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to set synchronous mode: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return -1;
    }

    // Create table if not exists (using the schema provided)
    const char *create_sql = 
        "CREATE TABLE IF NOT EXISTS packets ("
        "    timestamp      INTEGER NOT NULL,"
        "    ether_protocol INTEGER NOT NULL,"
        "    ip_protocol    INTEGER NOT NULL,"
        "    ip1            BLOB NOT NULL,"
        "    ip2            BLOB NOT NULL,"
        "    port1          INTEGER NOT NULL,"
        "    port2          INTEGER NOT NULL,"
        "    packet_size    INTEGER NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(timestamp);";

    rc = sqlite3_exec(db, create_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to create table: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return -1;
    }

    // Prepare insert statement
    const char *insert_sql = "INSERT INTO packets (timestamp, ether_protocol, ip_protocol, ip1, ip2, port1, port2, packet_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &insert_stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1;
    }

    *db_out = db;
    return 0;
}

void db_close(sqlite3 *db) {
    if (insert_stmt) {
        sqlite3_finalize(insert_stmt);
        insert_stmt = NULL;
    }
    if (db) {
        sqlite3_close(db);
    }
}

void db_begin(sqlite3 *db) {
    sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);
}

void db_commit(sqlite3 *db) {
    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
}

int db_insert_packet(sqlite3 *db, 
                     int64_t timestamp,
                     int ether_proto,
                     int ip_proto,
                     const void *ip1,
                     const void *ip2,
                     int ip_len,
                     uint16_t port1,
                     uint16_t port2,
                     int packet_size) {
    
    if (!insert_stmt) return -1;

    sqlite3_bind_int64(insert_stmt, 1, timestamp);
    sqlite3_bind_int(insert_stmt, 2, ether_proto);
    sqlite3_bind_int(insert_stmt, 3, ip_proto);
    sqlite3_bind_blob(insert_stmt, 4, ip1, ip_len, SQLITE_STATIC);
    sqlite3_bind_blob(insert_stmt, 5, ip2, ip_len, SQLITE_STATIC);
    sqlite3_bind_int(insert_stmt, 6, port1);
    sqlite3_bind_int(insert_stmt, 7, port2);
    sqlite3_bind_int(insert_stmt, 8, packet_size);

    int rc = sqlite3_step(insert_stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Insert failed: %s\n", sqlite3_errmsg(db));
        sqlite3_reset(insert_stmt);
        return -1;
    }

    sqlite3_reset(insert_stmt);
    return 0;
}
