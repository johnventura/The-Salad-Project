#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
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
#include "global.h"


void *sendproberequest(void *threadid);
int sendframe(uint8_t * buf, int buflen, char *intname);
int getmonsock(char *intname);
int setchannel(char *intname, int channel);

#define PAUSETEMPLATE "\x00\x00\x26\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x02\x00\x00\xff\xff\xff\xff\xff\xff\x00\x15\x6d\x85\x98\x84\x3c\x15\xc2\xe1\xfb\x50\x50\x40\xaa\xaa\x03\x00\x00\x00\x88\x08\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x63\x61\x6e\x27\x74\x20\x6f\x70\x65\xec\x50\x78\xa"

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

int usage(char *progname) {
    printf("Usage:\n");
    printf("%s\n", progname);
    printf("\t-h\tDisplays this message\n");
    printf("\t-i\tinterface to use\t(example: wlan0)\n");
    printf("\t-c\tchannel to use\n");
    return (0);
}


int main(int argc, char *argv[]) {
    int c;
    int sock;
    int pktlen;
    uint8_t *pos;
    uint8_t *pkt;
    struct wifi_tag *tag;
    struct wifi_header *wh;
    struct wifi_probe *wp;
    struct radiotap_header *rth;
    struct ifreq ifr;

    int rval;
    pthread_t threads[5];

    while ((c = getopt(argc, argv, "c:hi:")) != -1) {
	switch (c) {
	case 'h':		// usage
	    usage(argv[0]);

	    exit(0);
	    break;
	case 'i':		// what interface do you want to use?
	    intname = optarg;
	    break;
	case 'c':
	    channelmask = optarg;
	    break;
	default:
	    break;
	}
    }



    sock = getmonsock(intname);
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
    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
	perror("can't retrieve etherenet index\n");
	exit(1);
    }

    if (pthread_create(&threads[0], NULL, sendproberequest, NULL) != 0) {
	perror("can't thread");
	exit(1);
    }

    pkt = (uint8_t *) malloc(MAXPACKET);
    if (pkt == NULL) {
	perror("can't allocate memory");
	exit(1);
    }

    rth = (struct radiotap_header *) pkt;

    for (rval = 0; rval >= 0; rval = read(sock, pkt, MAXPACKET)) {
	if (rval > 0) {
	    pktlen = rval - rth->len;
	    wh = (struct wifi_header *) (pkt + rth->len);
	    wp = (struct wifi_probe *) (pkt + rth->len +
					sizeof(struct wifi_header));


	    if (wh->type == 0x50) {
		// start processing all the tags
		// this for loop goes through them
		for (pos = (uint8_t *) wp->tag;
		     pos < (uint8_t *) wp->tag + pktlen;
		     pos += (tag->len + 2)) {
		    tag = (struct wifi_tag *) pos;
		    // if it defines an ESSID
		    // compare it against the one we oant
		    if (tag->type == 0x00) {
			//write(1, tag->contents, tag->len);
			// if essid matches the one we want
			// return the bssid
			if (memcmp
			    (essid, tag->contents,
			     strlen((char *) essid)) == 0) {
			    printf("handshake detected\n");

			    // DESTROY HERE!!!!!!
			    close(sock);
			    free(pkt);
			    return (0);
			}
		    }

		}
	    }


	}
    }

    return (0);
}
