CC = gcc
CFLAGS = -O3
PROGNAME = ewok.salad


default:
	$(CC) $(CFLAGS) -c CryptoShenanigans.c
	$(CC) $(CFLAGS) -c global.c
	$(CC) $(CFLAGS) -c network.c
	$(CC) $(CFLAGS) -c http.c
	$(CC) $(CFLAGS) ewok.c  http.o global.o CryptoShenanigans.o network.o -lcurl -o $(PROGNAME)

clean:
	rm -f *.o $(PROGNAME)
