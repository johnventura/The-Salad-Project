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

#include <stdint.h>
// definitions for parsing wifi headers
// specific for wifi probes

struct wifi_header {
    uint8_t type;		// subtype (4bits) type (2bits) version (2bits)
    uint8_t flags;		// 
    uint16_t duration;
    uint8_t dest[6];
    uint8_t src[6];
    uint8_t bssid[6];
    uint16_t seq;
};

struct wifi_probe {
    uint8_t timestamp[8];
    uint16_t beacon;		// time between probes in seconds
    uint16_t paramtags;
    uint8_t tag[];
};

struct wifi_tag {
    uint8_t type;
    uint8_t len;
    uint8_t contents[];
};

struct radiotap_header {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    uint32_t present;
};

#define WIFIHEADER_DSSEND	0x01
#define WIFIHEADER_DSRECV	0x02
#define WIFIHEADER_FRAGMENTS	0x04	// is it a fragment
#define WIFIHEADER_RETRY	0x08	// is this a retransmission
#define WIFIHEADER_PWRMGT	0x10	// STA
#define WIFIHEADER_PROTECT	0x20	// Is data protected
#define WIFIHEADER_ORDER	0x40	// Is data strictly ordered?

#define BSSIDLEN		0x06
