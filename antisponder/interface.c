#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/socket.h>

uint32_t remoteip;
uint32_t remotebcast;

int guessintname(char *intname, int namelen) {
    struct ifaddrs *ifap, *ifa;
    int buflen = namelen;
    char *outbuf = "";

    getifaddrs(&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	if (ifa->ifa_addr->sa_family == AF_INET) {
	    outbuf = ifa->ifa_name;
	}
    }
    if (strlen(outbuf) < buflen)
	buflen = strlen(outbuf);
    memcpy(intname, outbuf, buflen);
    intname[strlen(outbuf)] = 0x00;
    freeifaddrs(ifap);
    return (0);
}

uint32_t getipv4addr(char *intname) {
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    uint32_t rval = 0;

    getifaddrs(&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	if ((ifa->ifa_addr->sa_family == AF_INET)
	    && !(strcmp(ifa->ifa_name, intname))) {
	    sa = (struct sockaddr_in *) ifa->ifa_addr;
	    rval = sa->sin_addr.s_addr;
	}
    }

    freeifaddrs(ifap);
    return (htonl(rval));
}

uint32_t getipv4bcast(char *intname) {
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    uint32_t rval = 0;

    getifaddrs(&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	if ((ifa->ifa_addr->sa_family == AF_INET)
	    && !(strcmp(ifa->ifa_name, intname))) {
	    sa = (struct sockaddr_in *) (ifa->ifa_ifu.ifu_broadaddr);
	    rval = sa->sin_addr.s_addr;
	}
    }

    freeifaddrs(ifap);
    return (htonl(rval));
}
