include ../platform-settings

CFLAGS:=$(CFLAGS) -I../jabberd/

dnsrv_HEADERS=srv_resolv.h ../jabberd/jabberd.h
dnsrv_OBJECTS=dnsrv.o dllinit.o
dnsrv_COOBJECTS=dnsrv_coprocess.o srv_resolv.o win32_resolv.o
jabberd_EXOBJECTS=	../jabberd/lib/xml*.o \
			../jabberd/lib/hashtable.o \
			../jabberd/lib/pool.o \
			../jabberd/lib/xstream.o \
			../jabberd/lib/str.o \
			../jabberd/lib/expat.o \
			../jabberd/lib/snprintf.o \
			../jabberd/lib/genhash.o \
			../jabberd/lib/xhash.o

single: static

all: dnsrv_build

$(dnsrv_OBJECTS): $(dnsrv_HEADERS)

dnsrv_build: $(dnsrv_OBJECTS) $(dnsrv_COOBJECTS) $(dnsrv_HEADERS)
	$(CC) $(CFLAGS) -o jabadns $(dnsrv_COOBJECTS) $(jabberd_EXOBJECTS) $(XLDFLAGS) $(LDFLAGS) $(SLIBS) $(PLINK) -liphlpapi
	dllwrap --def dnsrv.def --driver-name $(CC) -o dnsrv.dll $(dnsrv_OBJECTS) ../jabberd/jabberd.a $(LDFLAGS)

static: $(dnsrv_OBJECTS) $(dnsrv_COOBJECTS) $(dnsrv_HEADERS)
	$(CC) $(CFLAGS) -o jabadns $(dnsrv_COOBJECTS) $(jabberd_EXOBJECTS) $(XLDFLAGS) $(LDFLAGS) $(SLIBS) $(PLINK) -liphlpapi

clean:
	rm -f $(dnsrv_OBJECTS) $(dnsrv_COOBJECTS) dnsrv.dll jabadns.exe *.exp *.a
