include ../platform-settings

CFLAGS:=$(CFLAGS) -I../jabberd/

CC=gcc

pthsock_server_OBJECTS=\
	io_select.o \
	server.o

pthsock_client_OBJECTS=\
	io_select.o \
	client.o

all: pthsock_server pthsock_client

pthsock_client: $(pthsock_client_OBJECTS)
	$(CC) $(CFLAGS) $(MCFLAGS) -o pthsock_client.so $(pthsock_client_OBJECTS) $(LDFLAGS) $(LIBS)

pthsock_server: $(pthsock_server_OBJECTS)
	$(CC) $(CFLAGS) $(MCFLAGS) -o pthsock_server.so $(pthsock_server_OBJECTS) $(LDFLAGS) $(LIBS)

clean:
	rm -f $(pthsock_server_OBJECTS) $(pthsock_client_OBJECTS) pthsock_client.so pthsock_server.so
