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
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "interface.h"
#include "rand.h"
#include "getcreds.h"
#include "nameres.h"


#define NBNAMELEN 32

int senddgram(uint32_t s_ip, uint32_t d_ip, uint16_t sport,
	      uint16_t dport, uint8_t * buf, int buflen);
int sendudp(uint32_t s_ip, uint32_t d_ip, uint16_t sport, uint16_t dport,
	    uint8_t * buf, int buflen);
int sendHTTPhash(char *username, char *password, char *host, char *url);


int firstlevelencode(char *str, uint8_t * outbuf) {
    int i;
    char *inbuf;

    inbuf = (char *) malloc(NBNAMELEN);
    if (inbuf == NULL) {
	perror("can't allocate memory\n");
	exit(1);
    }
    memset(inbuf, 0x20, NBNAMELEN);
    inbuf[(NBNAMELEN / 2) - 1] = 0x00;
    if (strlen(str) > NBNAMELEN)
	str[NBNAMELEN / 2] = 0x00;
    memcpy(inbuf, str, strlen(str));
    // covert lower to upper case
    for (i = 0; i < strlen(str); i++) {
	if ((inbuf[i] >= 'a') && (inbuf[i] <= 'z'))
	    inbuf[i] -= 32;
    }

    for (i = 0; i < NBNAMELEN / 2; i++) {
	outbuf[i * 2] = (inbuf[i] >> 4) + 0x41;
	outbuf[(i * 2) + 1] = (inbuf[i] & 0x0f) + 0x41;
    }
    outbuf[NBNAMELEN] = 0x00;
    free(inbuf);
    return (0);
}

struct nbnsq *querynbns(char *hostname) {
    struct nbnsq *nq;

    nq = (struct nbnsq *) malloc(sizeof(struct nbnsq));
    if (nq == NULL) {
	perror("can't allocate memory\n");
	exit(1);
    }
    memset(nq, 0x00, sizeof(struct nbnsq));

    nq->transaction_id = getrand16();
    nq->flags = htons(0x0110);
    nq->questions = htons(0x0001);
    nq->name[0] = 0x20;
    firstlevelencode(hostname, nq->name + 1);
    nq->type = htons(0x0020);	// type == NB
    nq->class = htons(0x0001);	// class = IN
    return (nq);
}

uint8_t *queryllmnr(char *hostname) {
    uint8_t *lq;
    int querylen;
    struct llmnrq_header *lqh;
    struct llmnrq_footer *lqf;

    if (strlen(hostname) > 0xff) {
	hostname[0xff] = 0x00;
    }
    querylen =
	sizeof(struct llmnrq_header) + sizeof(struct llmnrq_footer) +
	strlen(hostname);

    lq = (uint8_t *) malloc(querylen);
    if (lq == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    memset(lq, 0x00, querylen);

    lqh = (struct llmnrq_header *) lq;
    lqf =
	(struct llmnrq_footer *) (lq + sizeof(struct llmnrq_header) +
				  strlen(hostname));

    lqh->transaction_id = getrand16();	// make this random
    lqh->questions = htons(0x0001);
    lqh->len = strlen(hostname);

    lqf->type = htons(0x0001);
    lqf->class = htons(0x0001);
    memcpy(lq + (sizeof(struct llmnrq_header) - 1), hostname,
	   strlen(hostname));

    return (lq);
}

int queryhost(char *hostname) {
    uint8_t *llmnrq;
    struct nbnsq *nq;
    nq = querynbns(hostname);

    sendudp(remoteip, remotebcast, 137, 137, (uint8_t *) nq,
	    sizeof(struct nbnsq));

    llmnrq = queryllmnr(hostname);
    sendudp(remotebcast, 0xe00000fc, getrand16(), 5355, (uint8_t *) llmnrq,
	    sizeof(struct llmnrq_header) + sizeof(struct llmnrq_footer) +
	    strlen(hostname));
    free(llmnrq);
    free(nq);
    return (0);
}

int parsellmnr(uint8_t * pkt, int pktlen, char *outstr) {
    struct llmnrq_header *lqh;
    uint8_t *name;

    lqh =
	(struct llmnrq_header *) (pkt + sizeof(struct iphdr) +
				  sizeof(struct udphdr));

    memset(outstr, 0x00, NBNAMELEN);
    if (lqh->rr_answer == 0) {
	return (0);
    }
    name = (uint8_t *) lqh + (sizeof(struct llmnrq_header) - 1);
    memcpy(outstr, name, lqh->len);

    return (0);
}

int parsenbns(uint8_t * pkt, int pktlen, char *outstr) {
    int i;
    int n;
    struct nbnsq *nq;

    nq = (struct nbnsq *) (pkt + sizeof(struct iphdr) +
			   sizeof(struct udphdr));

    memset(outstr, 0x00, NBNAMELEN);
    // there are no answers to read, so just quit
    if (nq->rr_answer == 0) {
	return (0);
    }
    // sanity check to make sure we don't parse bad input
    for (i = 1; i <= NBNAMELEN; i++) {
	if ((nq->name[i] < 'A') || (nq->name[i] > 'P')) {
	    return (0);
	}
    }
    n = 0;
    for (i = 1; i <= NBNAMELEN; i += 2) {
	outstr[n++] =
	    (((nq->name[i] - 0x41) << 4) | (nq->name[i + 1] - 0x41));

    }

    return (0);
}

uint32_t resolvehost4(char *host) {
    uint32_t ip;
    struct hostent *hp;
    ip = inet_addr(host);
    if (ip == INADDR_NONE) {
#ifndef STATIC			// gethostbyname() doesn't like static compilation
	hp = gethostbyname(host);
	memcpy(&ip, hp->h_addr, 4);
#endif
    }
    return (ip);
}
