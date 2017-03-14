int destroy(uint32_t ip, char *fakename, char **user, char **pass,
	    int mask);
int destroyhash(uint32_t ip, char *fakename, char **user, char **pass);
int destroyflood(uint32_t ip, char *fakename, char **user, char **pass);
int destroylog(uint32_t ip, char *fakename, char **user, char **pass);
int getdestroymask(char *str);


#define DES_LOG		0x01
#define DES_HASH	0x02
#define DES_FLOOD	0x04

struct destbl {
    char *str;
    int value;
};

extern const struct destbl destab[];


struct destroyargs {
    uint32_t ip;
    char *fakename;
};
