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
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include "eth.h"
#include "rand.h"
#include "getbssid.h"

// return a monitor socket
int getmonsock(char *intname) {
    int sock;
    struct sockaddr_ll sa;
    struct ifreq ifr;

    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
	perror("can't open socket\n");
	exit(1);
    }

    strncpy(ifr.ifr_name, intname, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
	perror("can't retrieve etherenet index\n");
	exit(1);
    }

    memset(&sa, 0x00, sizeof(sa));
    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = ifr.ifr_ifindex;
    sa.sll_hatype = htons(0x0001);
    sa.sll_pkttype = (PACKET_BROADCAST);
    sa.sll_halen = 6;

    return (sock);
}

// find a BSSID/MAC Address associated with an ESSID/Network Name
uint8_t *getbssidfromessid(char *essid, char *intname) {
    int sock;
    int rval;
    uint8_t *pkt;
    struct radiotap_header *rth;
    struct wifi_header *wh;
    struct wifi_probe *wp;
    struct wifi_tag *tag;
    uint8_t *pos;
    uint8_t *bssid;
    int pktlen;
    sock = getmonsock(intname);

    pkt = (uint8_t *) malloc(MAXPACKET);
    if (pkt == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    bssid = (uint8_t *) malloc(BSSIDLEN);
    if (bssid == NULL) {
	perror("can't allocate memory");
	exit(1);
    }


    rth = (struct radiotap_header *) pkt;

    // read all the raw packets we can get
    for (rval = 0; rval >= 0; rval = read(sock, pkt, MAXPACKET)) {
	// if we read a packet, start doing stuff
	if (rval > 0) {
	    pktlen = rval - rth->len;
	    wh = (struct wifi_header *) (pkt + rth->len);
	    wp = (struct wifi_probe *) (pkt + rth->len +
					sizeof(struct wifi_header));
	    tag = (struct wifi_tag *) wp->tag;
	    pos = (uint8_t *) wp->tag;
	    // if it's a beacon frame, start processing it
	    if (wh->type == 0x80) {
		// start processing all the tags
		// this for loop goes through them
		for (pos = (uint8_t *) wp->tag;
		     pos < (uint8_t *) wp->tag + pktlen;
		     pos += (tag->len + 2)) {
		    tag = (struct wifi_tag *) pos;
		    // if it defines an ESSID
		    // compare it against the one we oant
		    if (tag->type == 0x00) {
			// if essid matches the one we want
			// return the bssid
			if (memcmp(essid, tag->contents, strlen(essid)) ==
			    0) {
			    memcpy(bssid, wh->bssid, BSSIDLEN);
			    close(sock);
			    free(pkt);
			    return (bssid);
			}
		    }

		}
	    }
	}
    }


    // if we got here, our read loop failed horribly
    // just return null and hope for the best
    close(sock);
    free(pkt);

    return (NULL);
}
