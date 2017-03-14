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
