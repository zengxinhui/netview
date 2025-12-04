CREATE TABLE IF NOT EXISTS packets (
    timestamp      INTEGER NOT NULL,
    ether_protocol INTEGER NOT NULL,
    ip_protocol    INTEGER NOT NULL,
    ip1            BLOB NOT NULL,
    ip2            BLOB NOT NULL,
    port1          INTEGER NOT NULL,
    port2          INTEGER NOT NULL,
    packet_size    INTEGER NOT NULL
);

-- Start with ONLY a timestamp index for time-range queries.
-- Add others only if specific read patterns demand it.
CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(timestamp);