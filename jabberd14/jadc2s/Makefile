include platform-settings

jadc2s_HEADERS= jadc2s.h xmlparse/xmlparse.h util/util.h mio/mio.h

jadc2s_OBJECTS = $(EXTRA_OBJECTS) \
	util/config.o \
	util/jid.o \
	util/log.o \
	util/nad.o \
	util/pool.o \
	util/sha.o \
	util/snprintf.o \
	util/str.o \
	util/xhash.o \
	mio/mio.o \
	xmlparse/xmlparse.o \
	xmlparse/xmlrole.o \
	xmlparse/xmltok.o \
	xmlparse/hashtable.o \
	clients.o \
	conn.o \
	connect.o \
    rate.o \
	jadc2s.o

all: $(jadc2s_OBJECTS) $(jadc2s_HEADERS)
	$(CC) $(CFLAGS) -o jadc2s $(jadc2s_OBJECTS) $(LDFLAGS) 

$(jadc2s_OBJECTS): $(jadc2s_HEADERS)

profile-clean:
	rm -f *.da gmon.out
clean:
	rm -f $(jadc2s_OBJECTS) jadc2s
