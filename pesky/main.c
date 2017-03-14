#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "network.h"
#include "getbssid.h"
#include "eapmap.h"
#include "rand.h"
#include "eap.h"

// convert an ethernet MAC or BSSID to a 6 byte buffer
// hopefully, the user can choose to use colons or not
// hopefullly it is also case insensitiive
uint8_t *asciitomac(char *macstr) {
    int i;
    char bytebuf[3];
    uint8_t *mac;
    char *endptr;

    if (strlen(macstr) < 12) {
	return (NULL);
    }
    endptr = macstr + strlen(macstr);

    mac = (uint8_t *) malloc(LEN_MAC);
    if (mac == NULL) {
	perror("can't allocate memory");
	exit(1);
    }

    for (i = 0; i < LEN_MAC; i++) {
	bytebuf[0] = *macstr++;
	bytebuf[1] = *macstr++;
	bytebuf[2] = 0x00;
	if (macstr[0] == ':') {
	    *macstr++;
	}
	if (macstr > endptr)
	    return (NULL);
	mac[i] = strtoul(bytebuf, NULL, 16);
    }

    return (mac);
}

int usage(char *progname) {
    printf("Usage:\n");
    printf("%s\n", progname);
    printf("\t-h\tDisplays this message\n");
    printf("\t-b\tBSSID of the AP\t(example: 00:01:02:0a:0b:0c)\n");
    printf("\t-e\tESSID of the wireless network\n");
    printf("\t-c\tWi-Fi channel to use\n");
    printf("\t-i\tinterface to use\t(example: wlan0)\n");
    printf
	("\t-p\taverage (probabilistic) time (in seconds) between fake handshakes\n");
    printf
	("\t-t\tabsolute (deterministic) time interval (in seconds) between fake handshakes\n");



    return (0);
}

int main(int argc, char *argv[]) {
    int c;			// needed to parse command line 
    int seconds = 0;		// wait time in seconds 0 == just send it now
    int prob = 0;		// are we using deterministic or probabilistic wait time
    int sleeptime;		// actual sleep time between transmissions

    int channel = 0;		// WiFi channel we want to use
    char *psk = NULL;		// network password
    char *essid = NULL;		// name of network we are impersonating
    char *intname = "mon0";	// name of wifie interface we use

    uint8_t *bssid = NULL;	// Access Point (AP) MAC address
    uint8_t *supmac = NULL;	// fake client's MAC address

    while ((c = getopt(argc, argv, "c:k:b:e:ht:p:i:")) != -1) {
	switch (c) {
	case 'b':		// set the BSSID
	    bssid = asciitomac(optarg);
	    if (bssid == NULL) {
		fprintf(stderr, "Can't read BSSID\n");
	    }
	    break;
	case 'e':		// set the ESSID (network name)
	    essid = optarg;
	    if (essid != NULL) {
		strtok(essid, "\n\r");	// get rid of trailing CRs
	    }
	    break;
	case 'k':		// PSK to use
	    psk = optarg;
	    break;
	case 'c':		// set the channel
	    channel = atoi(optarg);
	    break;
	case 't':		// send EAP every "t" seconds
	    seconds = atoi(optarg);
	    break;
	case 'p':		// send EAP every "t" seconds on average
	    seconds = atoi(optarg);
	    break;
	case 'i':		// what interface do you want to use?
	    intname = optarg;
	    break;
	case 'h':		// probably help
	    usage(argv[0]);
	    exit(0);
	    break;
	default:
	    break;
	}
    }
    // allow user to use iwconfig to set the channel
    // or set it here
    if (channel != 0) {
	setmonitor(intname);
	setchannel(intname, channel);
    }
    // if we didn't set the BSSID set it here
    // if ESSID is set, then query the air for the BSSID
    if ((bssid == NULL) && (essid != NULL)) {
	bssid = getbssidfromessid(essid, intname);
    }
    // make up a BSSID, if we have to
    if (bssid == NULL) {
	bssid = (uint8_t *) malloc(LEN_MAC);
	if (bssid == NULL) {
	    perror("can't allocate memory");
	    exit(1);
	}
	fillbuf(bssid, LEN_MAC);
    }
    // pick out a PSK from command line or make one up
    if (psk == NULL) {
	psk = (char *) malloc(64);	// 64 characters is max len for WPA2 PSKs
	if (psk == NULL) {
	    perror("can't allocate memory");
	    exit(1);
	}
	fillstr(psk, 20, CHAREVERYTHING);
	psk[20] = 0x00;
    } else {
	// if the PSK is at the end of the command line we will have annoying CRs
	strtok(psk, "\n\r");	// get rid of trailing CRs
    }
    // thie is the client's MAC address
    if (supmac == NULL) {
	supmac = (uint8_t *) malloc(LEN_MAC);
	if (supmac == NULL) {
	    perror("can't allocate memory");
	    exit(1);
	}
	fillbuf(supmac, LEN_MAC);
    }
    // if we didn't define a time, just send it once
    if (seconds == 0) {
	sendeap(bssid, supmac, essid, psk, intname);
    } else {
	// send the EAPs in a loop
	for (;;) {

	    sendeap(bssid, supmac, essid, psk, intname);
	    // if we are using probilistic time, make sleep time random
	    // otherwise, set it to "seconds"
	    if (prob) {
		sleeptime = getrand16() % (seconds * 2);
	    } else {
		sleeptime = seconds;
	    }
	    sleep(sleeptime);
	}
    }
    free(bssid);

    return (0);
}
