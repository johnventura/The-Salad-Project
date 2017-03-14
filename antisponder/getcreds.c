#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "getcreds.h"
#include "rand.h"

#define MAXUSERLEN 64

//take a file list and return a string array
struct creddb *getuserlist(char *filename) {
    int linecount;
    char *buf;
    int i;
    char **username;
    char **pass;
    FILE *src;
    struct creddb *creds;

    creds = (struct creddb *) malloc(sizeof(struct creddb));
    if (creds == NULL) {
	perror("can't open file");
	exit(1);
    }

    src = fopen(filename, "rb");
    if (src == NULL) {
	perror("can't open file");
	exit(1);
    }
    //count the lines
    buf = (char *) malloc(MAXUSERLEN);
    if (buf == NULL) {
	perror("can't allocate memory");
	exit(1);
    }
    for (linecount = 0; fgets(buf, MAXUSERLEN, src); linecount++);
    free(buf);

    //start over and read the file again
    fseek(src, 0x00, SEEK_SET);

    username = malloc((linecount + 1) * (sizeof(char *)));
    if (username == NULL) {
	perror("can't allocate memory");
	exit(1);
    }

    pass = malloc((linecount + 1) * (sizeof(char *)));
    if (pass == NULL) {
	perror("can't allocate memory");
	exit(1);
    }

    for (i = 0; i < linecount; i++) {
	username[i] = (char *) malloc(MAXUSERLEN);
	if (username[i] == NULL) {
	    perror("can't allocate memory");
	    exit(1);
	}
	if (fgets(username[i], MAXUSERLEN, src) == NULL) {
	    //if we can't read the file anymore, stop trying
	    break;
	}
	username[i] = strtok(username[i], CREDDELIM);
	pass[i] = strtok(NULL, CREDDELIM);
	if ((pass[i] == NULL) || (strlen(pass[i]) == 0)) {
	    // FILL IN THE PASSWORD
	    pass[i] = (char *) malloc(MAXUSERLEN);
	    if (pass[i] == NULL) {
		perror("can't allocate memory");
		exit(1);
	    }
	    fillstr(pass[i], getrand8() % 8 + 10, CHAREVERYTHING);
	}
    }
    // trailing NULL lets us know list is over
    username[i + 1] = NULL;
    pass[i + 1] = NULL;
    creds->users = username;
    creds->passwords = pass;

    fclose(src);
    return (creds);
}

int countusers(char **users) {
    int rval;
    for (rval = 0; users[rval] != NULL; rval++);
    return (rval);
}
