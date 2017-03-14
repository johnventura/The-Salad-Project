#include <netinet/in.h>

extern uint32_t remoteip;
extern uint32_t remotebcast;


#define MAXINTLEN 512

int guessintname(char *intname, int namelen);
uint32_t getipv4addr(char *intname);
uint32_t getipv4bcast(char *intname);
