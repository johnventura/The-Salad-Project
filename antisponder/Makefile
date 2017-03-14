CC = gcc
CFLAGS = -O3 -Wall
PROGNAME = antisponder.salad

default: all

all:
	$(CC) $(CFLAGS) -c destroy.c 
	$(CC) $(CFLAGS) -c rand.c
	$(CC) $(CFLAGS) -c udp.c
	$(CC) $(CFLAGS) -c interface.c
	$(CC) $(CFLAGS) -c getcreds.c
	$(CC) $(CFLAGS) -c nameres.c
	$(CC) $(CFLAGS) main.c udp.o rand.o destroy.o interface.o getcreds.o nameres.o -lcurl -lpthread -o $(PROGNAME)

clean:
	rm -f *.o $(PROGNAME)
