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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <curl/curl.h>
#include "destroy.h"
#include "rand.h"
#include "getcreds.h"

int rval;

const struct destbl destab[] = {
    {"log", DES_LOG},
    {"hash", DES_HASH},
    {"flood", DES_FLOOD},
    {NULL, 0}
};


static size_t donothing(void *ptr, size_t size, size_t nmemb, void *stream) {
    rval = size;
    return (0);
}

int sendHTTPhash(char *username, char *password, char *host, char *url) {
    struct curl_slist *chunk = NULL;
    FILE *devnull = NULL;
    CURL *curl;
    CURLcode res;
    char *hostheader = "Host: ";

    rval = 0;

    curl = curl_easy_init();
    if (curl) {
	if (host != NULL) {
	    hostheader =
		(char *) malloc(strlen(host) + strlen(hostheader));
	    if (hostheader == NULL) {
		perror("can't allocate memory");
		exit(1);
	    }
	    sprintf(hostheader, "Host: %s", host);
	    chunk = curl_slist_append(chunk, hostheader);
	    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
	}
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, (long) CURLAUTH_ANY);
	curl_easy_setopt(curl, CURLOPT_USERNAME, username);
	curl_easy_setopt(curl, CURLOPT_PASSWORD, password);

	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, donothing);
	devnull = fopen("/dev/null", "wb");
	if (devnull == NULL) {
	    perror("can't open /dev/null");
	    exit(1);
	}
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, devnull);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
	    curl_easy_strerror(res);
	}
	curl_easy_cleanup(curl);
    }
    if (host != NULL) {
	free(hostheader);
    }
    fclose(devnull);
    return (rval);
}

int destroy(uint32_t ip, char *fakename, char **user, char **pass,
	    int mask) {
    if (mask & DES_LOG) {
	destroylog(ip, fakename, user, pass);
    }
    if (mask & DES_HASH) {
	destroyhash(ip, fakename, user, pass);
    }
    if (mask & DES_FLOOD) {
	destroyflood(ip, fakename, user, pass);
    }

    return (0);
}

int destroyhash(uint32_t ip, char *fakename, char **user, char **pass) {
    char *url;
    int urllen = 32;		// only need 24 for URL
    int diditwork;
    int usernumber;
    uint8_t octets[4];

    octets[0] = ip & 0xff;
    octets[1] = (ip >> 8) & 0xff;
    octets[2] = (ip >> 16) & 0xff;
    octets[3] = (ip >> 24) & 0xff;

    if (user == NULL) {
	perror("No users listed\n");
	exit(1);
    }

    usernumber = getrand16() % countusers(user);

    url = (char *) malloc(urllen);
    if (url == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    sprintf(url, "https://%i.%i.%i.%i/", octets[0], octets[1], octets[2],
	    octets[3]);
    diditwork =
	sendHTTPhash(user[usernumber], pass[usernumber], fakename, url);
    if (diditwork == 0) {

	sprintf(url, "http://%i.%i.%i.%i/", octets[0], octets[1],
		octets[2], octets[3]);
	sendHTTPhash(user[usernumber], pass[usernumber], fakename, url);
    }

    free(url);
    return (0);
}

int destroyflood(uint32_t ip, char *fakename, char **user, char **pass) {
    char *url;
    int urllen = 32;		// only need 24 for URL
    int diditwork;
    uint8_t octets[4];
    char *username;
    char *password;
    int fieldlen = 0xff;
    int i;

    username = (char *) malloc(fieldlen);
    if (username == NULL) {
	perror("can't allocaet memory");
	exit(1);
    }
    password = (char *) malloc(fieldlen);
    if (password == NULL) {
	perror("can't allocaet memory");
	exit(1);
    }

    octets[0] = ip & 0xff;
    octets[1] = (ip >> 8) & 0xff;
    octets[2] = (ip >> 16) & 0xff;
    octets[3] = (ip >> 24) & 0xff;

    url = (char *) malloc(urllen);
    if (url == NULL) {
	perror("can't allocate memory");
	exit(1);
    }

    for (i = 0; i < 0xffff; i++) {
	fillstr(username, fieldlen, CHARALPHALOWER);
	fillstr(password, fieldlen, CHAREVERYTHING);
	sprintf(url, "https://%i.%i.%i.%i/", octets[0], octets[1],
		octets[2], octets[3]);
	diditwork = sendHTTPhash(username, password, fakename, url);
	if (diditwork == 0) {

	    sprintf(url, "http://%i.%i.%i.%i/", octets[0], octets[1],
		    octets[2], octets[3]);
	    sendHTTPhash(username, password, fakename, url);
	}

    }
    free(username);
    free(password);
    free(url);
    return (0);
}

int destroylog(uint32_t ip, char *fakename, char **user, char **pass) {
    uint8_t octets[4];

    octets[0] = ip & 0xff;
    octets[1] = (ip >> 8) & 0xff;
    octets[2] = (ip >> 16) & 0xff;
    octets[3] = (ip >> 24) & 0xff;

    printf("Detected spoofing at %i.%i.%i.%i\n", octets[0],
	    octets[1], octets[2], octets[3]);
    
	openlog(PROGNAME, LOG_CONS | LOG_NDELAY, LOG_AUTH);
	syslog(LOG_WARNING, "blah");
    syslog(LOG_WARNING, "Detected spoofing at %i.%i.%i.%i\n", octets[0],
	    octets[1], octets[2], octets[3]);
	closelog();

    return (0);
}


int getdestroymask(char *str) {
    char *p;
    char *q;
    int mask = 0;
    int i;

    for (p = str; (q = strtok(p, ", ")); p = NULL) {
	for (i = 0; destab[i].str != NULL; i++) {
	    if (!strncmp(q, destab[i].str, strlen(destab[i].str))) {
		mask = mask | destab[i].value;
	    }
	}
    }
    return (mask);
}
