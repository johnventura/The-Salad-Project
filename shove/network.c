#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <linux/filter.h>
#include <arpa/inet.h>
#include "network.h"


// resolve hostnames for DNS
uint32_t resolveipv4(char *host) {
    uint32_t ip = 0x00000000;
    struct hostent *hp;

    ip = inet_addr(host);
    if (ip == INADDR_NONE) {
#ifndef STATIC			// gethostbyname() doesn't like static compilation
	hp = gethostbyname(host);
	if (hp != NULL) {
	    memcpy(&ip, hp->h_addr, 4);
	}
#endif
    }
    return (ip);
}


// return a raw socket in PROMISC mode
int getrawsock(char *intname) {
    int sock;
    struct ifreq ifr;
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
	perror("can't open raw socket");
	exit(1);
    }
    memset(&ifr, 0x00, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, intname, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
	perror("can't get socket info");
	exit(1);
    }
    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
	perror("can't set promic");
	exit(1);
    }
    return (sock);
}

// checksums for makeing packets
u_int16_t in_cksum(u_int16_t * addr, int len) {
    register int nleft = len;
    register u_int16_t *w = addr;
    register int sum = 0;
    u_short answer = 0;

    while (nleft > 1) {
	sum += *w++;
	nleft -= 2;
    }

    if (nleft == 1) {
	*(u_char *) (&answer) = *(u_char *) w;
	sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
    sum += (sum >> 16);		/* add carry */
    answer = ~sum;		/* truncate to 16 bits */
    return (answer);
}

// send an individual TCP packet
int sendtcp(u_int32_t s_ip, u_int32_t d_ip, u_int16_t sport,
	    u_int16_t dport, unsigned char *buf, u_int16_t buflen,
	    int seqoffset, int acknumber, uint16_t id) {
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct sockaddr_in sin;
    struct pseudohdr *pseudo;
    unsigned char *pkt;
    int one = 1;
    int pktlen;
    int sock;

    pktlen = sizeof(struct iphdr) + sizeof(struct tcphdr) + buflen;

    pkt = (unsigned char *) malloc(pktlen);
    if (pkt == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    memset(pkt, 0x00, pktlen);
    memcpy(pkt + sizeof(struct iphdr) + sizeof(struct tcphdr), buf,
	   buflen);

    ip = (struct iphdr *) pkt;
    tcp = (struct tcphdr *) (pkt + sizeof(struct iphdr));
    pseudo =
	(struct pseudohdr *) (pkt + (sizeof(struct iphdr) -
				     sizeof(struct pseudohdr)));

    pseudo->saddr = s_ip;
    pseudo->daddr = d_ip;
    pseudo->protocol = 6;
    pseudo->len = htons(sizeof(struct tcphdr) + buflen);

    tcp = (struct tcphdr *) (pkt + sizeof(struct iphdr));
    tcp->source = sport;
    tcp->dest = dport;
    tcp->seq = seqoffset;
    tcp->ack_seq = acknumber;
    tcp->psh = 1;
    tcp->ack = 1;
    tcp->window = htons(400);
    tcp->urg_ptr = 0;
    tcp->doff = 5;
    tcp->check = in_cksum((u_int16_t *) pseudo, (sizeof(struct tcphdr) +
						 sizeof(struct pseudohdr) +
						 buflen));

    ip->saddr = s_ip;
    ip->daddr = d_ip;
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 123;
    ip->tot_len =
	htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + buflen);
    ip->id = id;
    ip->protocol = 0x06;
    ip->check = 0;
    ip->check = in_cksum((u_int16_t *) pkt, sizeof(struct iphdr));

    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);
    sin.sin_addr.s_addr = d_ip;

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
	perror("can't open socket");
	exit(1);
    }

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
	perror("setting socket options");
	exit(1);
    }
    if (sendto
	(sock, pkt, pktlen, 0, (struct sockaddr *) &sin,
	 sizeof(struct sockaddr)) < 0) {
	perror("sending packet");
	exit(1);
    }
    free(pkt);
    close(sock);
    return (0);
}

// rap the sendtcp() function to send larger bufffers
int sendtcpdata(u_int32_t s_ip, u_int32_t d_ip, u_int16_t sport,
		u_int16_t dport, unsigned char *buf, u_int16_t buflen,
		int seqoffset, int acknumber, uint16_t id, int direction) {
    uint32_t i;
    // RFC879 says we can send up to 536 bytes in each packet. 
    // 512 is easier to debug
    int segsize = 512;

    for (i = 0; i < buflen; i = i + segsize) {
	if ((i + segsize) > buflen) {
	    segsize = (buflen - i);
	}
	sendtcp(s_ip, d_ip, sport, dport, (buf + i), segsize,
		(seqoffset + htonl(i)), acknumber, id);
    }
    return (0);
}
