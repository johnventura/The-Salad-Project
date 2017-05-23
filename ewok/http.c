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
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <linux/filter.h>
#include <arpa/inet.h>


#include <curl/curl.h>
#include "network.h"


struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *) userp;

    mem->memory = realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory == NULL) {
	/* out of memory! */
	printf("not enough memory (realloc returned NULL)\n");
	return 0;
    }

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

// download a file to the heap
// set *outbuf to that heap segment
// return the size of the file
// stole a lot of this code from libcurl docs
int urltomem(char *url, char *cookie, uint8_t ** outbuf)
{
    CURL *curl_handle;
    CURLcode res;
    struct MemoryStruct chunk;
    char *session;
    char *header = "session=";


    session = (char *) malloc(strlen(header) + strlen(cookie));
    if (session == NULL) {
	perror("can't allocate memory");
	exit(1);
    }

    sprintf(session, "session=%s", cookie);

    chunk.memory = malloc(1);
    if (chunk.memory == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    chunk.size = 0;		/* no data at this point */

    curl_global_init(CURL_GLOBAL_ALL);

    /* init the curl session */
    curl_handle = curl_easy_init();

    /* specify URL to get */
    curl_easy_setopt(curl_handle, CURLOPT_URL, url);

    /* send all data to this function  */
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION,
		     WriteMemoryCallback);

    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &chunk);

    /* some servers don't like requests that are made without a user-agent
       field, so we provide one */
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT,
		     "(Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko");
    //curl_easy_setopt(curl_handle, CURLOPT_COOKIE, "session=oiq1A1dJGeDB2lxcYA1oqMMYy38=");

    curl_easy_setopt(curl_handle, CURLOPT_COOKIE, session);

    /* get it! */
    res = curl_easy_perform(curl_handle);

    /* check for errors */
    if (res != CURLE_OK) {
	fprintf(stderr, "curl_easy_perform() failed: %s\n",
		curl_easy_strerror(res));
    }


    *outbuf = chunk.memory;
    curl_easy_cleanup(curl_handle);

    /* we're done with libcurl, so clean it up */
    curl_global_cleanup();

    return (chunk.size);
}
