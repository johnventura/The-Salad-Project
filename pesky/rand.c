#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>


// get random 16 bit #
uint16_t getrand16() {
    int fd;
    uint16_t rand;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
	perror("can't read /dev/urandom");
	exit(1);
    }
    if (read(fd, &(rand), 2) == 0) {
	rand = 0x00;
    }

    close(fd);
    return (rand);
}


// get random 16 bit #
uint8_t getrand8() {
    int fd;
    uint8_t rand;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
	perror("can't read /dev/urandom");
	exit(1);
    }
    if (read(fd, &(rand), 1) == 0) {
	rand = 0x00;
    }

    close(fd);
    return (rand);
}

// fill a string with random stuff
// "mode" is actually a string with charactes you want to choose from
int fillstr(char *str, int len, char *mode) {
    int i;
    for (i = 0; i < len; i++) {
	str[i] = mode[getrand16() % strlen(mode)];
    }
    str[i] = 0x00;
    return (0);
}

// fill a buffer with random values
void fillbuf(uint8_t * buf, int len) {
    int fd;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
	perror("can't read /dev/urandom");
	exit(1);
    }

    if (read(fd, buf, len) == 0) {
	memset(buf, 0x00, len);
    }
    close(fd);
}
