CC=gcc
DEFINES=-DCONFIGXML="\"jabberd.xml\""
CFLAGS=-fPIC -g $(DEFINES) -I./ -I../ `libxode-config --cflags` -Wall
LDFLAGS=`libxode-config --ldflags --libs` `pth-config --libs --ldflags` `jabber-config --ldflags --libs` -ldl

SUBDIRS = \
	gen \
	io \
	log \
	xdb

jabberd_OBJECTS = \
	config.o \
	deliver.o \
	heartbeat.o \
	jabberd.o \
	load.o \
	log.o \
	gen/base_host.o \
	io/base_connect.o \
	io/base_exec.o \
	io/base_stdout.o \
	io/base_load.o \
	io/base_accept.o \
	log/base_file.o \
	log/base_format.o \
	log/base_logtype.o \
	log/base_stderr.o \
	log/base_to.o \
	xdb/base_cache.o \
	xdb/base_ns.o

all: jabberd_build

jabberd_build: $(jabberd_OBJECTS)
	$(CC) -fPIC -export-dynamic -o jabberd $(jabberd_OBJECTS) $(LDFLAGS)

clean:
	rm $(jabberd_OBJECTS) jabberd
