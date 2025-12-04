#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <cap-ng.h>
#include "db.h"

#define BUFFER_SIZE 65536
#define BATCH_SIZE 10000
#define MIN_COMMIT_INTERVAL 1

volatile sig_atomic_t stop = 0;

void handle_signal(int sig) {
    stop = 1;
}

void drop_privileges() {
    capng_clear(CAPNG_SELECT_BOTH);
    const char *sudo_uid = getenv("SUDO_UID");
    const char *sudo_gid = getenv("SUDO_GID");
    
    if (sudo_uid && sudo_gid) {
        uid_t uid = atoi(sudo_uid);
        gid_t gid = atoi(sudo_gid);
        
        // We need CAP_NET_ADMIN to bind to raw socket, but we do that BEFORE dropping.
        // Wait, actually we need to keep CAP_NET_RAW if we want to keep using the socket?
        // No, once the socket is opened, we can drop privileges.
        
        if (capng_change_id(uid, gid, CAPNG_DROP_SUPP_GRP | CAPNG_CLEAR_BOUNDING)) {
            perror("capng_change_id");
            exit(EXIT_FAILURE);
        }
    } else {
        // If not running under sudo, we might be root directly. 
        // In that case, we can't easily know which user to drop to.
        // For now, only drop if SUDO_UID is present.
        fprintf(stderr, "Warning: Not running under sudo, privileges not dropped.\n");
    }
}

int main() {
    int sock_raw;
    struct sockaddr_ll sll;
    struct ifreq ifr;
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);
    
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // Open raw socket
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket Error");
        return 1;
    }

    // Get interface index
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "wlan0", IFNAMSIZ - 1);
    if (ioctl(sock_raw, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        close(sock_raw);
        free(buffer);
        return 1;
    }

    // Bind to interface
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock_raw, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock_raw);
        free(buffer);
        return 1;
    }

    // Initialize Database
    sqlite3 *db;
    if (db_init("packets.db", &db) != 0) {
        close(sock_raw);
        free(buffer);
        return 1;
    }

    // Change ownership of DB files to the sudo user so they can access it later
    const char *sudo_uid = getenv("SUDO_UID");
    const char *sudo_gid = getenv("SUDO_GID");
    if (sudo_uid && sudo_gid) {
        uid_t uid = atoi(sudo_uid);
        gid_t gid = atoi(sudo_gid);
        chown("packets.db", uid, gid);
        chown("packets.db-wal", uid, gid);
        chown("packets.db-shm", uid, gid);
    }

    // Drop privileges
    drop_privileges();

    printf("Sniffer started on wlan0...\n");

    int batch_count = 0;
    time_t last_commit_time = time(NULL);
    db_begin(db);

    while (!stop) {
        int data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (data_size < 0) {
            if (stop) break;
            continue;
        }

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        int64_t timestamp_ns = (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;

        struct ethhdr *eth = (struct ethhdr *)buffer;
        uint16_t ether_proto = ntohs(eth->h_proto);
        
        int ip_proto = 0;
        unsigned char src_ip[16] = {0};
        unsigned char dst_ip[16] = {0};
        int ip_len = 0;
        uint16_t src_port = 0;
        uint16_t dst_port = 0;

        if (ether_proto == ETH_P_IP) {
            struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
            unsigned short iphdrlen = iph->ihl * 4;
            
            ip_proto = iph->protocol;
            ip_len = 4;
            memcpy(src_ip, &iph->saddr, 4);
            memcpy(dst_ip, &iph->daddr, 4);

            if (ip_proto == IPPROTO_TCP) {
                struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + iphdrlen);
                src_port = ntohs(tcph->source);
                dst_port = ntohs(tcph->dest);
            } else if (ip_proto == IPPROTO_UDP) {
                struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct ethhdr) + iphdrlen);
                src_port = ntohs(udph->source);
                dst_port = ntohs(udph->dest);
            }
            // ICMP ports are 0, which is default
        } else if (ether_proto == ETH_P_IPV6) {
            struct ip6_hdr *ip6h = (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));
            
            ip_proto = ip6h->ip6_nxt;
            ip_len = 16;
            memcpy(src_ip, &ip6h->ip6_src, 16);
            memcpy(dst_ip, &ip6h->ip6_dst, 16);

            // Handle extension headers loop if needed, but for basic sniffing:
            // We assume next header is L4 or ICMPv6. 
            // Real IPv6 parsing is complex due to extension headers. 
            // For this task, we'll check the immediate next header.
            
            if (ip_proto == IPPROTO_TCP) {
                struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
                src_port = ntohs(tcph->source);
                dst_port = ntohs(tcph->dest);
            } else if (ip_proto == IPPROTO_UDP) {
                struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
                src_port = ntohs(udph->source);
                dst_port = ntohs(udph->dest);
            }
            // ICMPv6 ports are 0
        }

        // Canonicalize IP/Port order
        // Compare byte arrays
        int swap = 0;
        if (ip_len > 0) {
            if (memcmp(src_ip, dst_ip, ip_len) > 0) {
                swap = 1;
            }
        }

        if (swap) {
            unsigned char temp_ip[16];
            memcpy(temp_ip, src_ip, ip_len);
            memcpy(src_ip, dst_ip, ip_len);
            memcpy(dst_ip, temp_ip, ip_len);
            
            uint16_t temp_port = src_port;
            src_port = dst_port;
            dst_port = temp_port;
        }

        db_insert_packet(db, timestamp_ns, ether_proto, ip_proto, src_ip, dst_ip, ip_len, src_port, dst_port, data_size);

        batch_count++;
        time_t current_time = time(NULL);
        if (batch_count >= BATCH_SIZE || current_time - last_commit_time >= MIN_COMMIT_INTERVAL) {
            db_commit(db);
            db_begin(db);
            batch_count = 0;
            last_commit_time = current_time;
        }
    }

    // Final commit
    db_commit(db);
    
    db_close(db);
    close(sock_raw);
    free(buffer);
    
    printf("Sniffer stopped.\n");
    return 0;
}
