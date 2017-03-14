CC = gcc
CFLAGS = -O3 -I/usr/include/libxml2
PROGNAME = shove

default: all

all:
	$(CC) $(CFLAGS) -c network.c
	$(CC) $(CFLAGS) -c -lxml2 readxml.c
	$(CC) $(CFLAGS) -c -lxml2 main.c
	$(CC) network.o readxml.o main.o -lxml2 -o $(PROGNAME)

clean:	
	rm network.o readxml.o main.o $(PROGNAME)
	
