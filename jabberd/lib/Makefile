#
# Ok this is taken from an automaked file and tweaked out
#
include ../../platform-settings

CFLAGS:=$(CFLAGS)

lib_HEADERS= \
	asciitab.h \
	hashtable.h \
	iasciitab.h \
	latin1tab.h \
	lib.h \
	nametab.h \
	utf8tab.h \
	xmldef.h \
	xmlparse.h \
	xmlrole.h \
	xmltok.h \
	xmltok_impl.h

lib_OBJECTS = \
    expat.o \
	genhash.o \
	hashtable.o \
	jid.o \
	jpacket.o \
	jutil.o \
	karma.o \
	pool.o \
	pproxy.o \
	rate.o \
	sha.o \
	snprintf.o \
	socket.o \
	str.o \
	xmlnode.o \
	xmlparse.o \
	xmlrole.o \
	xmltok.o \
	xhash.o \
	xstream.o

$(lib_OBJECTS): $(lib_HEADERS)

single: static

static: $(lib_OBJECTS) $(lib_HEADERS)

all: $(lib_OBJECTS) $(lib_HEADERS)

clean:
	rm -f $(lib_OBJECTS) jabberd
