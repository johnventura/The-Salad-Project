#include <stdint.h>

int sendframe(uint8_t * buf, int buflen, char *intname);
int setchannel(char *intname, int channel);
int setmonitor(char *intname);
uint8_t getchannel(char *intname);
