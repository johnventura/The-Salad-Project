#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

int sendudp(uint32_t s_ip, uint32_t d_ip, uint16_t sport, uint16_t dport,
	    uint8_t * buf, int buflen) {
    int sock;
    struct sockaddr_in daddr;
    struct sockaddr_in saddr;
    int one = 1;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock <= 0) {
	perror("Can't open socket");
	exit(1);
    }

    daddr.sin_family = AF_INET;
    daddr.sin_addr.s_addr = htonl(d_ip);
    daddr.sin_port = htons(dport);

    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(s_ip);
    saddr.sin_port = htons(sport);

    if (bind(sock, (const struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
	perror("can't bind socket");
	exit(1);
    }

    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
    sendto(sock, buf, buflen, 0, (const struct sockaddr *) &daddr,
	   sizeof(struct sockaddr_in));

    close(sock);

    return (0);
}
