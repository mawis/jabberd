include ../platform-settings

CFLAGS=$(CCFLAGS) -I../jabberd/

HEADERS=../jabberd/jabberd.h

pthsock_client_OBJECTS=\
	client.o

single: static

all: pthsock_client

$(pthsock_client_OBJECTS): $(HEADERS)

pthsock_client: $(pthsock_client_OBJECTS) $(HEADERS)
	$(CC) $(CFLAGS) $(MCFLAGS) -o pthsock_client.so $(pthsock_client_OBJECTS) $(LDFLAGS) $(LIBS)

static: $(pthsock_client_OBJECTS) $(HEADERS)

clean:
	rm -f $(pthsock_client_OBJECTS) pthsock_client.so
