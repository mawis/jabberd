CC=gcc
CFLAGS=-fPIC -shared -g -I./ -I../ `libxode-config --cflags` -Wall -lresolv -I../jabberd

all: dnsrv_build

dnsrv_build: srv_resolv.h
	$(CC) $(CFLAGS) -o dnsrv.so dnsrv.c srv_resolv.c

clean:
	rm -f dnsrv.so
