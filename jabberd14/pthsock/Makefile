CFLAGS=-fPIC -g $(DEFINES) -I./ -I../ -I../jabberd `libxode-config --cflags` `jabber-config --cflags` -Wall
LDFLAGS=`libxode-config --ldflags --libs` `pth-config --libs --ldflags` `jabber-config --ldflags --libs` -ldl

all: pthsock_server_new pthsock_client_new pthsock_client_old pthsock_server_old

pthsock_client_old:
	gcc -fPIC -shared -o pthsock_client.so pthsock_client.c $(CFLAGS) $(LDFLAGS)

pthsock_client_new:
	gcc -fPIC -shared -o pthsock_client_new.so io_select.c client.c $(CFLAGS) $(LDFLAGS)

pthsock_server_old:
	gcc -fPIC -shared -o pthsock_server.so pthsock_server.c $(CFLAGS) $(LDFLAGS)

pthsock_server_new:
	gcc -fPIC -shared -o pthsock_server_new.so server.c io_select.c $(CFLAGS) $(LDFLAGS)

clean:
	rm -f pthsock_client.so pthsock_server.so
