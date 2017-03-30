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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "eth.h"
#include "eapmap.h"
#include "rand.h"
#include "network.h"

#define PROBEREQUEST_TAGS "\x01\x04\x02\x04\x0b\x16\x32\x08\x0c\x12\x18\x24\x30\x48\x60\x6c\x2d\x1a\x2d\x00\x17\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7f\x08\x04\x00\x08\x84\x00\x00\x00\x40\x6b\x07\x0f\xff\xff\xff\xff\xff\xff\xdd\x0b\x00\x17\xf2\x0a\x00\x01\x04\x00\x00\x00\x00\xdd\x08\x00\x50\xf2\x08\x00\x10\x00\x00\xdd\x09\x00\x10\x18\x02\x00\x00\x10\x00\x00"


struct wifi_proberesponse {
    uint8_t type;
    uint8_t flags;
    uint16_t duration;
    uint8_t destmac[6];
    uint8_t srcmac[6];
    uint8_t bssid[6];
    uint16_t sequence;
};

struct __attribute__ ((packed, aligned(1)))
    proberequest {
    struct radiotap_header radiotap;
    uint8_t padding[10];
    struct wifi_proberesponse probe;
};


int hexdump(uint8_t * buf, int buflen) {
    int i;
    int pos;

    pos = 0;
    printf("\n");
    for (i = 0; i < buflen; i++) {
	printf("%02x ", buf[i]);
	pos++;
	if (pos == 16) {
	    printf("\n");
	    pos = 0;
	}
	if (pos == 8) {
	    printf("  ");
	}
    }
    printf("\n");
    return (0);
}


int sendprobes() {
    uint8_t *packet;
    int probelen;
    struct proberequest *pr;
    struct wifi_tag *tag;

    // ARGS
    uint8_t *localmac = (uint8_t *) "\x40\x33\x1a\xec\x52\x74";
    uint8_t *essid = (uint8_t *) "VENTURA-NET";
    char *intname = "wlan0";
    //

    // 2 == tag headers for ssid tab
    // 3 == tag headers and one byte for frequency
    // 4 == 32 bit CRC
    probelen =
	sizeof(struct proberequest) + strlen((char *) essid) + 2 + 3 + 4 +
	sizeof(PROBEREQUEST_TAGS);

    packet = (uint8_t *) malloc(probelen);
    if (packet == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    memset(packet, 0x00, probelen);
    pr = (struct proberequest *) packet;

    pr->radiotap.len = 0x12;

    pr->probe.type = 0x40;
    memset(pr->probe.destmac, 0xff, LEN_MAC);
    memcpy(pr->probe.srcmac, localmac, LEN_MAC);
    memset(pr->probe.bssid, 0xff, LEN_MAC);
    pr->probe.sequence = getrand16();

    tag = (struct wifi_tag *) (packet + sizeof(struct proberequest));
    tag->len = strlen((char *) essid);
    memcpy(tag->contents, essid, strlen((char *) essid));
    tag =
	(struct wifi_tag *) (packet + sizeof(struct proberequest) +
			     strlen((char *) essid) + 2);
    tag->type = 0x03;
    tag->len = 0x01;
    tag->contents[0] = getchannel(intname);
    memcpy((uint8_t *) tag + 4, PROBEREQUEST_TAGS,
	   sizeof(PROBEREQUEST_TAGS));
    printf("%i\n", sizeof(struct proberequest));
    printf("%i\n", sizeof(PROBEREQUEST_TAGS));


    hexdump((uint8_t *) pr, probelen);

    free(pr);
    return (0);
}
