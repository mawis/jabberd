CC=gcc
CFLAGS=-fPIC -g -shared $(DEFINES) -I./ -I../ -I../jabberd `libxode-config --cflags` `jabber-config --cflags` -Wall
LDFLAGS=`libxode-config --ldflags --libs` `pth-config --libs --ldflags` `jabber-config --ldflags --libs` -ldl

pthsock_server_OBJECTS=\
	io_select.o \
	server.o

pthsock_client_OBJECTS=\
	io_select.o \
	client.o

all: pthsock_server pthsock_client

pthsock_client: $(pthsock_client_OBJECTS)
	$(CC) $(CFLAGS) -o pthsock_client.so $(pthsock_client_OBJECTS) $(LDFLAGS)

pthsock_server: $(pthsock_server_OBJECTS)
	$(CC) $(CFLAGS) -o pthsock_server.so $(pthsock_server_OBJECTS) $(LDFLAGS)

clean:
	rm -f $(pthsock_server_OBJECTS) $(pthsock_client_OBJECTS) pthsock_client.so pthsock_server.so
