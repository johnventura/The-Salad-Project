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
