include ../platform-settings

CFLAGS=$(CCFLAGS) -I../jabberd/

HEADERS=../jabberd/jabberd.h

pthsock_client_OBJECTS= client.o

ifeq ($(__CYGWIN__),1)
pthsock_client_OBJECTS+= ../cygwin/dllinit.o
endif

single: static

all: pthsock_client

$(pthsock_client_OBJECTS): $(HEADERS)

pthsock_client: $(pthsock_client_OBJECTS) $(HEADERS)
ifeq ($(__CYGWIN__),1)
# Make .def file:
	echo EXPORTS > pthsock_client.def
	nm $(pthsock_client_OBJECTS) $(PTHLIB) | grep '^........ [T] _' | sed 's/[^_]*_//' | sort >> pthsock_client.def
	dllwrap --def pthsock_client.def --driver-name $(CC) -o pthsock_client.dll $(pthsock_client_OBJECTS) ../jabberd/jabberd.a $(LDFLAGS) $(LIBS)
else
	$(CC) $(CFLAGS) $(MCFLAGS) -o pthsock_client.so $(pthsock_client_OBJECTS) $(LDFLAGS) $(LIBS)
endif

static: $(pthsock_client_OBJECTS) $(HEADERS)

clean:
ifeq ($(__CYGWIN__),1)
	rm -f $(pthsock_client_OBJECTS) pthsock_client.dll *.a *.def *.exp
else
	rm -f $(pthsock_client_OBJECTS) pthsock_client.so
endif
