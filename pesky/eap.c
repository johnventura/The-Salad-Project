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
#include <string.h>
#include <stdint.h>

#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "network.h"
#include "eapmap.h"
#include "rand.h"

// calculates a 32 bit CRC for a given memory buffer
// used for the last 4 bytes of the second EAP packet 
// stolen from here https://rosettacode.org/wiki/CRC-32#C 
uint32_t generatecrc32(uint32_t crc, uint8_t * buf, size_t len) {
    static uint32_t table[256];
    static int have_table = 0;
    uint32_t rem;
    uint8_t octet;
    int i, j;
    uint8_t *p, *q;

    /* This check is not thread safe; there is no mutex. */
    if (have_table == 0) {
	/* Calculate CRC table. */
	for (i = 0; i < 256; i++) {
	    rem = i;		/* remainder from polynomial division */
	    for (j = 0; j < 8; j++) {
		if (rem & 1) {
		    rem >>= 1;
		    rem ^= 0xedb88320;
		} else
		    rem >>= 1;
	    }
	    table[i] = rem;
	}
	have_table = 1;
    }

    crc = ~crc;
    q = buf + len;
    for (p = buf; p < q; p++) {
	octet = *p;		/* Cast to unsigned octet. */
	crc = (crc >> 8) ^ table[(crc & 0xff) ^ octet];
    }
    return ~crc;
}

// makes the PTK for calculating the MIC
// stolen from ettercap
uint8_t *generatePTK(u_char * bssid, u_char * sta, u_char * pmk,
		     u_char * snonce, u_char * anonce, uint16_t bits) {
    uint8_t i;
    unsigned int len;
    uint8_t buff[100];
    unsigned char *kck;
    size_t offset = sizeof("Pairwise key expansion");

    memset(buff, 0, 100);

    /* initialize the buffer */
    memcpy(buff, "Pairwise key expansion", offset);

    /*   Min(AA, SPA) || Max(AA, SPA)  */
    if (memcmp(sta, bssid, ETH_ADDR_LEN) < 0) {
	memcpy(buff + offset, sta, ETH_ADDR_LEN);
	memcpy(buff + offset + ETH_ADDR_LEN, bssid, ETH_ADDR_LEN);
    } else {
	memcpy(buff + offset, bssid, ETH_ADDR_LEN);
	memcpy(buff + offset + ETH_ADDR_LEN, sta, ETH_ADDR_LEN);
    }

    /* move after AA SPA */
    offset += ETH_ADDR_LEN * 2;

    /*   Min(ANonce,SNonce) || Max(ANonce,SNonce)  */
    if (memcmp(snonce, anonce, WPA_NONCE_LEN) < 0) {
	memcpy(buff + offset, snonce, WPA_NONCE_LEN);
	memcpy(buff + offset + WPA_NONCE_LEN, anonce, WPA_NONCE_LEN);
    } else {
	memcpy(buff + offset, anonce, WPA_NONCE_LEN);
	memcpy(buff + offset + WPA_NONCE_LEN, snonce, WPA_NONCE_LEN);
    }

    /* move after ANonce SNonce */
    offset += WPA_NONCE_LEN * 2;
    kck = (unsigned char *) malloc(WPA_PTK_LEN);
    if (kck == NULL) {
	perror("can't allocate memory");
	exit(1);
    }

    memset(kck, 0, WPA_PTK_LEN);

    /* generate the PTK */
    for (i = 0; i < (bits + 159) / 160; i++) {
	buff[offset] = i;

	/* the buffer (ptk) is large enough (see declaration) */
	HMAC(EVP_sha1(), pmk, WPA_KEY_LEN, buff, 100, kck + i * 20, &len);
    }

    return (kck);
}

// generates the PMK for calculating the MIC.
// pass == network password
// salt == ESSID or network name
uint8_t *generatePMK(const char *pass, char *salt) {
    unsigned char digest[WPA_PMK_LEN];
    uint8_t *pmk;

    pmk = (uint8_t *) malloc(WPA_PMK_LEN);
    if (pmk == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    PKCS5_PBKDF2_HMAC_SHA1((char *) pass, strlen((char *) pass),
			   (unsigned char *) salt, strlen(salt), 4096,
			   WPA_PMK_LEN, digest);
    memcpy(pmk, digest, WPA_PMK_LEN);
    return (pmk);
}

// sends first and second EAP packets through an interface
// in "monitor mode" 
// bssid == AP's MAC
// supmac == client's MAC
// essid == network name
// psk == network password
// intname == name of interface
int sendeap(uint8_t * bssid, uint8_t * supmac, char *essid,
	    char *psk, char *intname) {
    uint8_t *kck;
    uint8_t *pmk;
    uint8_t *mic;
    uint8_t *anonce;
    uint8_t *snonce;
    uint8_t *eapol1;
    uint8_t *eapol2;
    uint32_t eapol2CRC;

    // fill in values here
    anonce = (uint8_t *) malloc(LEN_NONCE);
    if (anonce == NULL) {
	perror("can't allocate memory");
	exit(1);
// outBytes == 32
    }
    snonce = (uint8_t *) malloc(LEN_NONCE);
    if (snonce == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    fillbuf(anonce, LEN_NONCE);
    fillbuf(snonce, LEN_NONCE);

    // EAPOL1 is made here
    eapol1 = (uint8_t *) malloc(EAP1_SIZE);
    if (eapol1 == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    // populate fields in EAPOL1 packet
    memcpy(eapol1, EAP1_TEMPLATE, EAP1_SIZE);
    memcpy(eapol1 + EAP1_OFFSET_SUPMAC, supmac, LEN_MAC);
    memcpy(eapol1 + EAP1_OFFSET_BSSID1, bssid, LEN_MAC);
    memcpy(eapol1 + EAP1_OFFSET_BSSID2, bssid, LEN_MAC);
    memcpy(eapol1 + EAP1_OFFSET_ANONCE, anonce, LEN_NONCE);
    // END EAPOL1


    // EAPOL2 is made here
    eapol2 = (uint8_t *) malloc(EAP2_SIZE);
    if (eapol2 == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    // populate fields in EAPOL2 packet
    memcpy(eapol2, EAP2_TEMPLATE, EAP2_SIZE);
    memcpy(eapol2 + EAP2_OFFSET_SUPMAC, supmac, LEN_MAC);
    memcpy(eapol2 + EAP2_OFFSET_BSSID1, bssid, LEN_MAC);
    memcpy(eapol2 + EAP2_OFFSET_BSSID2, bssid, LEN_MAC);
    memcpy(eapol2 + EAP2_OFFSET_SNONCE, snonce, LEN_NONCE);

    // start calculating the MIC
    pmk = generatePMK(psk, (char *) essid);

    kck = generatePTK(bssid, supmac, pmk, anonce, snonce, 32);
    mic =
	HMAC(EVP_sha1(), kck, LEN_MIC,
	     (uint8_t *) (eapol2 + EAP2_OFFSET_MIC_START),
	     EAP2_OFFSET_MIC_STOP, NULL, NULL);
    // put the MIC in EAPOL2
    memcpy(eapol2 + EAP2_OFFSET_MIC, mic, LEN_MIC);
    // put the "frame check sequence" in EAPOL2
    eapol2CRC =
	generatecrc32(0, (eapol2 + EAP2_OFFSET_CRC_START),
		      EAP2_OFFSET_CRC_STOP);
    memcpy((eapol2 + EAP2_OFFSET_CRC), &eapol2CRC, 4);
    // end EAPOL2

    sendframe(eapol1, EAP1_SIZE, intname);
    sendframe(eapol2, EAP2_SIZE, intname);
    free(kck);
    free(pmk);
    free(eapol1);
    free(eapol2);
    free(anonce);
    free(snonce);

    return (0);
}
