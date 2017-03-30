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

struct nbnsq *querynbns(char *hostname);
uint8_t *queryllmnr(char *hostname);
int queryhost(char *hostname);
int parsellmnr(uint8_t * pkt, int pktlen, char *outstr);
int parsenbns(uint8_t * pkt, int pktlen, char *outstr);
uint32_t resolvehost4(char *hostname);

#define NBNAMELEN 32
#define NBNAMEMIN 8

struct nbnsq {
    uint16_t transaction_id;
    uint16_t flags;
    uint16_t questions;
    uint16_t rr_answer;
    uint16_t rr_authority;
    uint16_t rr_additional;
    uint8_t name[34];
    uint16_t type;
    uint16_t class;
};

struct llmnrq_header {
    uint16_t transaction_id;
    uint16_t flags;
    uint16_t questions;
    uint16_t rr_answer;
    uint16_t rr_authority;
    uint16_t rr_additional;
    uint8_t len;
};

struct llmnrq_footer {
    uint16_t type;
    uint16_t class;
};
