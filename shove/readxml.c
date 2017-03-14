#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <libxml/xmlreader.h>
#include "readxml.h"

// function prototype(s)
uint32_t resolveipv4(char *host);

// convvert a string to reslove "escaped" characters
// instr == user supplied string with escaped characters, like "%0a"
// outstr == where "unescaped" data goes
// the return value is the length of "outstr"
// PLEASE watch buffer length for outstr
int decodestr(char *instr, uint8_t * outstr) {
    int i;
    int pos = 0;
    char hexbuf[3];
    char *endptr;
    long int intbuf;
    uint8_t *bytebuf;

    bytebuf = (uint8_t *) & intbuf;

    for (i = 0; i < strlen(instr); i++) {
	if (instr[i] == '%') {
	    hexbuf[0] = instr[i + 1];
	    hexbuf[1] = instr[i + 2];
	    hexbuf[2] = 0x00;
	    intbuf = strtol(&hexbuf[0], &endptr, 16);
	    outstr[pos++] = bytebuf[0];

	    i = i + 2;
	} else {
	    outstr[pos++] = instr[i];
	}

    }

    return (pos);
}

// search and replace raw binary data
// inbuf is going to get changed
// every instance of "old" will be repalced with "new"
// "old" and "new" are of inbuflen bytes
int replacebuf(uint8_t * inbuf, uint8_t * old, uint8_t * new, int inbuflen,
	       int newlen) {
    int i;

    for (i = 0; i < (inbuflen - newlen); i++) {
	if (memcmp(inbuf + i, old, newlen) == 0) {
	    memcpy(inbuf + i, new, newlen);
	}
    }
    return (0);
}

// return a linked list with signatures and responses
// ip is the IP of the listner
struct sigentry *readsigfile(char *filename, uint32_t ip) {
    int ret;
    int sig = -1;
    const xmlChar *name, *value;
    uint8_t *signature = NULL;
    uint8_t *rtype = NULL;
    uint8_t *response = NULL;
    uint8_t *signame = NULL;
    int direction = 0;
    int signaturelen = 0;
    int responselen = 0;
    char *cmd = NULL;
    char *resolvehost;
    int havesignature = 0;
    int haveresponse = 0;
    int havertype = 0;
    int havename = 0;
    int havedirection = 0;
    struct sigentry *se = NULL;
    struct sigentry *senext = NULL;
    struct sigentry *sereturn = NULL;

    xmlTextReaderPtr reader;

    reader = xmlReaderForFile(filename, NULL, 0);
    ret = xmlTextReaderRead(reader);

    cmd = (char *) malloc(MAXTAGLEN);
    if (cmd == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    while (ret == 1) {
	name = xmlTextReaderConstName(reader);
	value = xmlTextReaderConstValue(reader);

	if ((name != NULL) && (strcmp((char *) name, "#text") != 0)) {
	    memset(cmd, 0x00, MAXTAGLEN);
	    memcpy(cmd, name, ISLESSER(strlen((char *) name), MAXTAGLEN));
	}
	// <console> defines the "listner" IP for revers shells
	if (!strncmp("console", cmd, 7)) {
	    if (value != NULL) {
		if (value != NULL) {
		    // get rid of whitespaces: space, cr, nl, and tab
		    resolvehost = strtok((char *) value, "\x20\x0a\x0d\x09");
		    if (resolvehost != NULL) {
			ip = resolveipv4(resolvehost);
		    }
		}
	    }
	}
	// <sig> says we are definingig a trigger/response
	if (!strcmp(cmd, "sig")) {
	    sig = sig * -1;
	    if (sig < 0) {
		// when we get a </sig>, start processing
		// we no longer have these fields figured out for the next sig
		havesignature = 0;
		haveresponse = 0;
		havertype = 0;
		havename = 0;
		havedirection = 0;
		// alllocate the next entry in the list
		senext =
		    (struct sigentry *) malloc(sizeof(struct sigentry));
		if (senext == NULL) {
		    perror("can't allocate memory");
		    exit(1);
		}

		senext->netsig = signature;
		senext->netsiglen = signaturelen;
		senext->response = response;
		senext->responselen = responselen;
		senext->name = (char *) signame;
		senext->direction = direction;
		senext->next = NULL;
		if (se == NULL) {
		    se = senext;	// this is the first in the sequence
		    sereturn = se;
		} else {
		    se->next = senext;	// 
		    se = senext;
		}
	    }
	    memset(cmd, 0x00, MAXTAGLEN);
	}
	if ((value != NULL) && (sig > 0)) {
	    // <trigger> is the pattern we are looking for
	    if (!strncmp("trigger", cmd, 7)) {
		if ((value != NULL) && (havesignature != 1)) {
		    signature = (uint8_t *) malloc(strlen((char *) value));
		    if (signature == NULL) {
			perror("can't allocate memory");
			exit(1);
		    }
		    // unescape the string we are looking for and figure out length
		    signaturelen = decodestr((char *) value, signature);
		    havesignature++;
		}
		// currently not implemented, but responses can be files in the future
	    } else if (!strncmp("rtype", cmd, 5)) {
		if ((value != NULL) && (havertype != 1)) {
		    rtype = (uint8_t *) malloc(strlen((char *) value));
		    if (rtype == NULL) {
			perror("can't allocate memory");
			exit(1);
		    }
		    decodestr((char *) value, rtype);
		    havertype++;
		}
		// what do we dump into the TCP stream 
	    } else if (!strncmp("response", cmd, 8)) {
		if ((value != NULL) && (haveresponse != 1)) {
		    response = (uint8_t *) malloc(strlen((char *) value));
		    if (response == NULL) {
			perror("can't allocate memory");
			exit(1);
		    }
		    // how much data do we shove into the stream?
		    // also, "unescape" the data
		    responselen = decodestr((char *) value, response);
		    // if we defined a console IP, replace the "magic" number
		    if (ip != 0x00000000) {
			replacebuf(response, (uint8_t *) DEFAULTIP,
				   (uint8_t *) & ip, responselen, 4);
		    }
		    haveresponse++;
		}
		// <name> defines the "name" for the signature
	    } else if (!strncmp("name", cmd, 4)) {
		if ((value != NULL) && (havename != 1)) {
		    signame = (uint8_t *) malloc(strlen((char *) value));
		    if (signame == NULL) {
			perror("can't allocate memory");
			exit(1);
		    }
		    // you can put escaped characters in names
		    decodestr((char *) value, signame);
		    havename++;
		}
		// <direction> forward means we append ; reverse means we respond
	    } else if (!strncmp("direction", cmd, 9)) {
		if ((value != NULL) && (havedirection != 1)) {
		    if (!strncmp((char *) value, "forward", 7)) {
			direction = SIGFORWARD;
		    } else {
			direction = SIGREVERSE;
		    }
		    havedirection++;
		}
	    }
	}
	ret = xmlTextReaderRead(reader);

    }

    xmlTextReaderRead(reader);

    return (sereturn);
}
