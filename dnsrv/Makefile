CC=gcc
CFLAGS=-fPIC -shared -g -I./ -I../ `libxode-config --cflags` -Wall -lresolv -I../jabberd

dnsrv_OBJECTS=dnsrv.o srv_resolv.o

all: dnsrv_build

dnsrv_build: $(dnsrv_OBJECTS)
	$(CC) $(CFLAGS) -o dnsrv.so $(dnsrv_OBJECTS) 

clean:
	rm -f $(dnsrv_OBJECTS) dnsrv.so
