#define MAXPACKET 2048

struct pseudohdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t unused;
    uint8_t protocol;
    uint16_t len;
};
