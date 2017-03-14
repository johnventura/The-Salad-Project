#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <libxml/xmlreader.h>

#define MAXTAGLEN 512
#define SIGFORWARD 0
#define SIGREVERSE 1
#define DEFAULTIP	"\xb7\xb7\xb7\xb7"
#define ISLESSER(a, b) ((a) > (b) ? (b) : (a))


//typedef struct sigentry {
struct sigentry {
    uint8_t *netsig;
    int netsiglen;
    uint8_t *response;
    int responselen;
    char *name;
    int direction;
    struct sigentry *next;
};
