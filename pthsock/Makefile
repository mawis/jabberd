CFLAGS=-fPIC -g $(DEFINES) -I./ -I../ -I../jabberd `libxode-config --cflags` `jabber-config --cflags` -Wall
LDFLAGS=`libxode-config --ldflags --libs` `pth-config --libs --ldflags` `jabber-config --ldflags --libs` -ldl

all: pthsock_client pthsock_server

pthsock_client:
	gcc -fPIC -shared -o pthsock_client.so pthsock_client.c $(CFLAGS) $(LDFLAGS)

pthsock_server:
	gcc -fPIC -shared -o pthsock_server.so pthsock_server.c $(CFLAGS) $(LDFLAGS)

clean:
	rm -f pthsock_client.so pthsock_server.so
