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
