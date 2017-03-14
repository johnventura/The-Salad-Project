CC = gcc
CFLAGS = -Wall -O3
PROGNAME = pesky.salad
ALTPROGNAME = sol.salad


default: prelim pesky.deps sol.deps

prelim:
	$(CC) $(CFLAGS) -c getbssid.c
	$(CC) $(CFLAGS) -c eap.c
	$(CC) $(CFLAGS) -c rand.c
	$(CC) $(CFLAGS) -c network.c
pesky.deps:
	$(CC) $(CFLAGS) getbssid.o network.o eap.o rand.o main.c -lcrypto -o $(PROGNAME)
pesky:	prelim pesky.deps

sol.deps:
	$(CC) $(CFLAGS) -c sendproberequest.c
	$(CC) $(CFLAGS) sniffloop.c getbssid.o sendproberequest.o rand.o network.o -o $(ALTPROGNAME) -lpthread
sol:	prelim sol.deps


clean:
	rm -f *.o $(PROGNAME) $(ALTPROGNAME)
