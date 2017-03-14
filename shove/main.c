#include <stdio.h>
#include <string.h>
#include <stdint.h>
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
#include "readxml.h"
#include "network.h"

// Function Prototypes
int getrawsock(char *intname);
int sendtcpdata(u_int32_t s_ip, u_int32_t d_ip, u_int16_t sport,
		u_int16_t dport, unsigned char *buf, u_int16_t buflen,
		int seqoffset, int acknumber, uint16_t id, int direction);
struct sigentry *readsigfile(char *filename, uint32_t ip);


// Basic documentation
int usage(char *progname) {
    printf("Usage:\n");
    printf("%s\n", progname);
    printf("\t-h\tDisplays this message\n");
    printf("\t-l\t<listener IP>\n");
    printf("\t-c\t<config file>\n");
    printf("\t-i\t<interface to monitor>\n");

    return (0);
}


int main(int argc, char *argv[]) {
    int sock;
    int pktlen;
    int payloadoffset;
    int c;
    uint8_t *pkt;
    uint8_t *tcppayload;
    uint32_t seqtmp;
    uint32_t acktmp;
    uint32_t listenerip = 0x00000000;
    struct iphdr *ip;
    struct tcphdr *tcp;
    char *interface = "eth0";
    char *xmlfilename;
    struct sigentry *sigtab;
    struct sigentry *thissig;
    struct sock_fprog fprog;
    struct sock_filter fil[] = {	// LPF filter for TCP packets
	{0x28, 0, 0, 0x0000000c},
	{0x15, 0, 5, 0x000086dd},
	{0x30, 0, 0, 0x00000014},
	{0x15, 6, 0, 0x00000006},
	{0x15, 0, 6, 0x0000002c},
	{0x30, 0, 0, 0x00000036},
	{0x15, 3, 4, 0x00000006},
	{0x15, 0, 3, 0x00000800},
	{0x30, 0, 0, 0x00000017},
	{0x15, 0, 1, 0x00000006},
	{0x6, 0, 0, 0x0000ffff},
	{0x6, 0, 0, 0x00000000},
    };


    while ((c = getopt(argc, argv, "hi:c:l:")) != -1) {
	switch (c) {
	case 'h':		// probably help
	    usage(argv[0]);
	    return (0);
	    break;
	case 'i':		// interface to monitor
	    interface = optarg;
	    break;
	case 'c':		// config file
	    xmlfilename = optarg;
	    break;
	case 'l':		// IP address of the listener
	    listenerip = resolveipv4(optarg);
	    break;
	default:
	    break;
	}
    }


    // read the XML config file
    sigtab = readsigfile(xmlfilename, listenerip);

    // open up a raw socket for sniffing
    sock = getrawsock(interface);
    // apply the LPF/BPF filter
    fprog.len = sizeof(fil) / sizeof(fil[0]);
    fprog.filter = fil;
    setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));

    // this is where we read packets into
    pkt = (uint8_t *) malloc(MAXPACKET);
    if (pkt == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    ip = (struct iphdr *) (pkt + (sizeof(struct ether_header)));
    tcp =
	(struct tcphdr *) (pkt + (sizeof(struct ether_header)) +
			   (sizeof(struct iphdr)));

    // this for loop is our sniff loop
    for (pktlen = 0; pktlen >= 0; pktlen = read(sock, pkt, MAXPACKET)) {
	if (pktlen > 0) {
	    // find where the TCP payloads are
	    payloadoffset =
		((sizeof(struct iphdr)) + (sizeof(struct ether_header)) +
		 (tcp->th_off * 4));
	    tcppayload = (uint8_t *) (pkt + payloadoffset);
	    // go through the signatures in the list one by one     
	    for (thissig = sigtab; thissig != NULL;
		 thissig = thissig->next) {
		if (memcmp(tcppayload, thissig->netsig, thissig->netsiglen)
		    == 0) {

		    if (thissig->direction == SIGREVERSE) {
			//spoof the response
			seqtmp =
			    htonl(ntohl(tcp->seq) + thissig->netsiglen);
			sendtcpdata(ip->daddr, ip->saddr, tcp->dest,
				    tcp->source, thissig->response,
				    thissig->responselen, tcp->ack_seq,
				    seqtmp, ip->id, SIGREVERSE);
		    } else {

			// append to a message
			seqtmp = htonl(ntohl(tcp->ack_seq));
			acktmp =
			    htonl(ntohl(tcp->seq) + thissig->netsiglen);

			sendtcpdata(ip->saddr, ip->daddr, tcp->source,
				    tcp->dest, thissig->response,
				    thissig->responselen, acktmp, seqtmp,
				    ip->id, SIGFORWARD);
		    }

		}
	    }

	}
    }

    return (0);
}
