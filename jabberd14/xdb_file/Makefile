include ../platform-settings

CFLAGS:=$(CFLAGS) -I../jabberd

xdb_file_OBJECTS=xdb_file.o

all: xdb_file

xdb_file: $(xdb_file_OBJECTS)
	$(CC) $(CFLAGS) $(MCFLAGS) -o xdb_file.so $(xdb_file_OBJECTS) $(LDFLAGS) $(LIBS)

static: $(xdb_file_OBJECTS)

clean:
	rm -f $(xdb_file_OBJECTS) xdb_file.so
