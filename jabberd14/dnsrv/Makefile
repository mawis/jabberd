CFLAGS=-fPIC -g $(DEFINES) -I./ -I../ -I../jabberd `libxode-config --cflags` `jabber-config --cflags` -Wall
LDFLAGS=`libxode-config --ldflags --libs` `pth-config --libs --ldflags` `jabber-config --ldflags --libs` -ldl

all: dnsrv

dnsrv:
	gcc -o dnsrv dnsrv.c $(CFLAGS) $(LDFLAGS)
#	gcc -fPIC -shared -o dnsrv.so dnsrv.c $(CFLAGS) $(LDFLAGS)

clean:
	rm -f dnsrv dnsrv.so
