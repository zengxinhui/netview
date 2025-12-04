#ifndef DB_H
#define DB_H

#include <stdint.h>
#include <sqlite3.h>

// Initialize the database connection
// Returns 0 on success, non-zero on error
int db_init(const char *db_path, sqlite3 **db_out);

// Close the database connection
void db_close(sqlite3 *db);

// Begin a transaction
void db_begin(sqlite3 *db);

// Commit a transaction
void db_commit(sqlite3 *db);

// Insert a packet into the database
// Returns 0 on success, non-zero on error
int db_insert_packet(sqlite3 *db, 
                     int64_t timestamp,
                     int ether_proto,
                     int ip_proto,
                     const void *ip1,
                     const void *ip2,
                     int ip_len,
                     uint16_t port1,
                     uint16_t port2,
                     int packet_size);

#endif // DB_H
