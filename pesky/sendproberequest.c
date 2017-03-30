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
#include <unistd.h>
#include "eth.h"
#include "eapmap.h"
#include "rand.h"
#include "network.h"
#include "global.h"

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



void *sendproberequest(void *threadid) {
    uint8_t *packet;
    int probelen;
    struct proberequest *pr;
    struct wifi_tag *tag;
    char *p, *q;
    int numberofchannels = 0;
    int *channellist;
    int i = 0;

    channellist = (int *) malloc(sizeof(int));
    if (channellist == NULL) {
	perror("can't allocate memory");
	exit(1);
    }

    for (p = channelmask; (q = strtok(p, " ,")); p = NULL) {
	printf("%s\n", q);
	channellist[numberofchannels] = atoi(q);
	channellist = realloc(channellist, ++numberofchannels);
	if (channellist == NULL) {
	    perror("can't allocate memory");
	    exit(1);
	}
	channellist[numberofchannels] = 0;
    }
    // put the interface in monitor mode
    // putting this before the sniff loop, so we don't keep doing it
    setmonitor(intname);

    for (;;) {
	localmac = (uint8_t *) malloc(LEN_MAC);
	if (localmac == NULL) {
	    perror("can't allocate memory");
	    exit(1);
	}
	essid = (uint8_t *) malloc(LEN_ESSID_MAX);
	if (essid == NULL) {
	    perror("can't allocate memory");
	    exit(1);
	}
	memset(essid, 0x00, LEN_ESSID_MAX);
	fillstr((char *) essid,
		LEN_ESSID_MIN + getrand16() % (LEN_ESSID_MAX -
					       LEN_ESSID_MIN),
		CHARALPHALOWER);
	fillbuf(localmac, LEN_MAC);

	probelen =
	    sizeof(struct proberequest) + strlen((char *) essid) + 2 + 3 +
	    4 + sizeof(PROBEREQUEST_TAGS);

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

	memcpy((uint8_t *) tag + 3, PROBEREQUEST_TAGS,
	       sizeof(PROBEREQUEST_TAGS));


	printf("SENDING QUERY FOR %s\n", essid);
	// if we are at the end of the list go back to the beginning
	if (numberofchannels != 0) {
	    if (channellist[i] == 0) {
		i = 0;
	    }
	    // set the channel to the next one on the list
	    printf("setting freq to %i\n", channellist[i]);
	    setchannel(intname, channellist[i++]);
	    // if we only want one channel, try not to set it again
	    if (numberofchannels == 1) {
		numberofchannels = 0;

	    }
	}
	sendframe((uint8_t *) pr, probelen, intname);

	free(packet);
	free(localmac);
	sleep(10);
    }
}
