CC=gcc
CFLAGS=-fPIC -shared -g -I./ -I../ `libxode-config --cflags` -Wall -I../jabberd

all: dnsrv_build

dnsrv_build: 
	$(CC) $(CFLAGS) -o dnsrv.so dnsrv.c

clean:
	rm -f dnsrv.so
