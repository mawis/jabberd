include ../platform-settings

CFLAGS:=$(CFLAGS) -I../jabberd/

CC=gcc

dnsrv_OBJECTS=dnsrv.o srv_resolv.o

all: dnsrv_build

dnsrv_build: $(dnsrv_OBJECTS)
	$(CC) $(CFLAGS) $(MCFLAGS) -o dnsrv.so $(dnsrv_OBJECTS) 

clean:
	rm -f $(dnsrv_OBJECTS) dnsrv.so
