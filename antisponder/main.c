#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include "interface.h"
#include "rand.h"
#include "getcreds.h"
#include "nameres.h"
#include "destroy.h"

#define MAXPACKETLEN 0xFFFF

char *fakehost;
int seconds;
int timemode;

int getrawsock(char *intname) {
    struct ifreq ifr;
    int sock;

    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
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
    if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
	perror("can't retrieve etherenet index\n");
	exit(1);
    }
    return (sock);
}
void *sendqueries() {
    int waittime;
    waittime = seconds;
    for (;;) {
	fillstr(fakehost, NBNAMEMIN + getrand8() % (NBNAMELEN - NBNAMEMIN),
		CHARALPHAUPPER);
	sleep(1);
	queryhost(fakehost);
	if (timemode == 1)
	    waittime = getrand8() % (seconds * 2);
	printf("sleeping for %i seconds\n", waittime);
	sleep(waittime);
    }
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    int sock;
    int pktlen;
    int c;
    uint8_t *pkt;
    char *resolved;
    struct iphdr *ip;
    struct udphdr *udp;
    pthread_t threads[5];
    char *interface = NULL;
    char **user = NULL;
    char **passwd = NULL;
    struct creddb *cdb = NULL;
    char *server = NULL;
    uint32_t serverip;
    int destroymask = DES_LOG;

    seconds = 300;		// default time interval
    timemode = 0;		// 0 == deterministic time
    user = NULL;

    while ((c = getopt(argc, argv, "hi:u:t:p:d:s:")) != -1) {
	switch (c) {
	case 'h':		// probably help
	    break;
	case 'i':		// interface to monitor
	    interface = optarg;
	    break;
	case 'u':		// list of users for hashes
	    cdb = getuserlist(optarg);
	    user = cdb->users;
	    passwd = cdb->passwords;
	    break;
	case 't':		// deterministic time
	    seconds = atoi(optarg);
	    break;
	case 'p':		// probabilistic time
	    seconds = atoi(optarg);
	    timemode = 1;
	    break;
	case 'd':		// options for "destroy" log|flood|hash
	    destroymask = getdestroymask(optarg);
	    break;
	case 's':		// server to "destroy"
	    server = optarg;
	    break;
	default:
	    break;
	}
    }

    if (server != NULL) {
	serverip = resolvehost4(server);
	resolved = "none";
	destroy(serverip, resolved, user, passwd, destroymask);
	return (0);
    }
    if (interface == NULL) {
	interface = (char *) malloc(MAXINTLEN);
	if (interface == NULL) {
	    perror("can't allocaet memory");
	    exit(1);
	}
	guessintname(interface, MAXINTLEN);
    }
    remoteip = getipv4addr(interface);
    remotebcast = getipv4bcast(interface);

    fakehost = (char *) malloc(NBNAMELEN + 1);
    if (fakehost == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    memset(fakehost, 0x00, NBNAMELEN + 1);

    if (pthread_create(&threads[0], NULL, sendqueries, NULL) != 0) {
	perror("can't thread");
	exit(0);
    }

    resolved = (char *) malloc(NBNAMELEN);
    if (resolved == NULL) {
	perror("can't allocate memory");
	exit(1);
    }

    pkt = (uint8_t *) malloc(MAXPACKETLEN);
    if (pkt == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    memset(pkt, 0x00, MAXPACKETLEN);
    ip = (struct iphdr *) (pkt + sizeof(struct ethhdr));
    udp =
	(struct udphdr *) (pkt + sizeof(struct iphdr) +
			   sizeof(struct ethhdr));

    printf("Listening on interface %s\n", interface);
    sock = getrawsock(interface);

    for (pktlen = 0; pktlen >= 0; pktlen = read(sock, pkt, MAXPACKETLEN)) {
	if (ip->protocol == 0x11) {
	    if (udp->dest == (htons(137))) {
		memset(resolved, 0x00, NBNAMELEN);
		printf("NBNS\n");
		parsenbns((uint8_t *) ip,
			  MAXPACKETLEN - (sizeof(struct iphdr) +
					  sizeof(struct iphdr)), resolved);
	    } else if (udp->source == (htons(5355))) {

		parsellmnr((uint8_t *) ip,
			   MAXPACKETLEN - (sizeof(struct iphdr) +
					   sizeof(struct iphdr)),
			   resolved);
		printf("LLMNR\n");
	    }
	    if ((strlen(resolved) > 0)
		&& (!strncasecmp(resolved, fakehost, strlen(fakehost)))) {
		destroy(ip->saddr, resolved, user, passwd, destroymask);
		resolved[0] = 0x00;	//no more destroying
	    }
	}
	memset(pkt, 0x00, MAXPACKETLEN);
    }

    return (0);
}
