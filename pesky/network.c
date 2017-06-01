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
#include <ifaddrs.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <asm/types.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "table.h"

// send a packet starting at *buf of buflen bytes
// to the network through the interface defined in intname
int sendframe(uint8_t * buf, int buflen, char *intname) {
    int sd;
    struct sockaddr_ll sa;
    struct ifreq ifr;

    sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sd < 0) {
	perror("can't open socket\n");
	exit(1);
    }
    printf("%s\n", intname);
    strncpy(ifr.ifr_name, intname, IFNAMSIZ);
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
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
    sa.sll_addr[6] = 0x00;
    sa.sll_addr[7] = 0x00;

    // keep spraying packets until timeout
    // if no timeout, just keep going
    sendto(sd, buf, buflen, 0, (struct sockaddr *) &sa, sizeof(sa));

    close(sd);
    return (0);
}

int setchannel(char *intname, int channel) {
    int sock;

    struct iwreq *iwr;

    iwr = malloc(sizeof(struct iwreq));
    if (iwr == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    memset(iwr, 0x00, sizeof(struct iwreq));

    iwr->u.freq.m = channel;
    iwr->u.freq.e = 0;		// no fractional frequencies
    iwr->u.freq.flags = IW_FREQ_FIXED;	// no channel hopping for us

    strncpy(iwr->ifr_name, intname, strlen(intname));

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	perror("can't open socket");
	exit(1);
    }

    if (ioctl(sock, SIOCSIWFREQ, iwr) < 0) {
	close(sock);
	free(iwr);
	perror("can't set frequency");
	exit(1);
    }

    free(iwr);
    close(sock);

    return (0);
}

uint8_t frequencytochannel(uint16_t frequency) {
    int i;
    uint8_t rval = 0;
    for (i = 0; freqtab[i].frequency != 0; i++) {
	if (freqtab[i].frequency == frequency) {
	    rval = freqtab[i].channel;
	}

    }
    return (rval);
}

uint8_t getchannel(char *intname) {
    int sock;
    uint8_t channel;
    struct iwreq *iwr;

    iwr = malloc(sizeof(struct iwreq));
    if (iwr == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    memset(iwr, 0x00, sizeof(struct iwreq));

    strncpy(iwr->ifr_name, intname, strlen(intname));
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	perror("can't open socket");
	exit(1);
    }
	if (ioctl(sock, SIOCGIWFREQ, iwr) < 0) {
		close(sock);
		free(iwr);
		perror("can't get frequency");
		exit(1);
        }

    channel = frequencytochannel(iwr->u.freq.m);
    free(iwr);
    close(sock);

    return (channel);		// make this channel
}

int setmonitor(char *intname) {
    int sock;

    struct iwreq *iwr;
    struct ifreq *ifr;

    iwr = malloc(sizeof(struct iwreq));
    if (iwr == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    strncpy(iwr->ifr_name, intname, strlen(intname));

    ifr = malloc(sizeof(struct ifreq));
    if (ifr == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    strncpy(ifr->ifr_name, intname, strlen(intname));

    // open up a socket for subsequent IOCTL calls
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	perror("can't open socket");
	exit(1);
    }
    // get the current mode settings for interface
    if (ioctl(sock, SIOCGIWMODE, iwr) < 0) {
	close(sock);
	free(iwr);
	perror("can't read mode");
	exit(1);
    }
    iwr->u.mode = IW_MODE_MONITOR;	// make it monitor mode

    // set monitor mode
    if (ioctl(sock, SIOCSIWMODE, iwr) < 0) {
	close(sock);
	free(iwr);
	perror("can't read mode");
	exit(1);
    }
    // get socket flags for subsquently setting interface to "up"
    if (ioctl(sock, SIOCGIFFLAGS, ifr) < 0) {
	close(sock);
	free(ifr);
	perror("can't read interface state");
	exit(1);
    }
    // these flags make the interface up and broadcast/multicast
    ifr->ifr_flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST;
    // DO IT!
    if (ioctl(sock, SIOCSIFFLAGS, ifr) < 0) {
	close(sock);
	free(ifr);
	perror("can't read interface state");
	exit(1);
    }

    free(iwr);
    free(ifr);
    close(sock);

    return (0);
}
