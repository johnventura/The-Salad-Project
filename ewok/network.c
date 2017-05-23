/*
BSD 3-Clause License

Copyright (c) 2017, John Ventura
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

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
#include "global.h"


// resolve hostnames for DNS
uint32_t resolveipv4(char *host)
{
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
int getrawsock(char *intname)
{
    int sock;
    struct ifreq ifr;
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
	perror("can't open raw socket");
	exit(1);
    }
    memset(&ifr, 0x00, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
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

// apply an LPF filter to a socket for TCP packets from/to "ip"
int filterIP(int sock, uint32_t ip)
{
    int i;
    uint32_t placeholder = 0xb7b7b7b7;
    uint32_t *lookhere;
    struct sock_filter template[] = {   // LPF filter for TCP packets
        {0x28, 0, 0, 0x0000000c},
        {0x15, 0, 5, 0x00000800},
        {0x20, 0, 0, 0x0000001e},
        {0x15, 0, 3, placeholder},
        {0x30, 0, 0, 0x00000017},
        {0x15, 0, 1, 0x00000006},
        {0x6, 0, 0, 0x0000ffff},
        {0x6, 0, 0, 0x00000000},
    };
    struct sock_fprog fprog;
    struct sock_filter **fil;

    fil = (struct sock_filter **) malloc(sizeof(template));
    if (fil == NULL) {
        perror("can't allocate memory");
        exit(1);
    }
    memcpy(fil, template, sizeof(template));


    // replace the "placeholder" with the IP you want
    lookhere = (uint32_t *) fil;
    for (i = 0; i < (sizeof(template) - sizeof(ip)); i++) {
        if (lookhere[i] == placeholder) {
            lookhere[i] = ip;
        }
    }

    fprog.len = sizeof(template) / sizeof(template[0]);
    fprog.filter = (struct sock_filter *) fil;
    setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));

    return (0);
}




// checksums for makeing packets
u_int16_t in_cksum(u_int16_t * addr, int len)
{
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
	    int seqoffset, int acknumber, uint16_t id, uint8_t flags)
{
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
    tcp->th_flags = flags;
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
		int seqoffset, int acknumber, uint16_t id, uint8_t flags,
		int direction)
{
    uint32_t i;
    // RFC879 says we can send up to 536 bytes in each packet. 
    // 512 is easier to debug
    int segsize = 512;

    for (i = 0; i < buflen; i = i + segsize) {
	if ((i + segsize) > buflen) {
	    segsize = (buflen - i);
	}
	sendtcp(s_ip, d_ip, sport, dport, (buf + i), segsize,
		(seqoffset + htonl(i)), acknumber, id, flags);
    }
    return (0);
}
