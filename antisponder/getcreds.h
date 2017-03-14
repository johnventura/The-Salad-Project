int chopstr(char *str);
struct creddb *getuserlist(char *filename);
int countusers(char **users);
char **getpasswordlist(int howmany);

// usernames and passwords are
// separated by spaces or tabs
// newlines and CRs are trimmed
#define CREDDELIM "\x20\t\r\n"

struct creddb {
    char **users;
    char **passwords;
};
