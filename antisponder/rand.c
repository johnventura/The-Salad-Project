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
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>


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

int fillstr(char *str, int len, char *mode) {
    int i;
    for (i = 0; i < len; i++) {
	str[i] = mode[getrand16() % strlen(mode)];
    }
    str[i] = 0x00;
    return (0);
}
