include ../../platform-settings

CC=gcc

xdb_HEADERS=../jabberd.h

xdb_OBJECTS=base_ns.o

$(xdb_OBJECTS): $(xdb_HEADERS)

all: $(xdb_OBJECTS) $(xdb_HEADERS)

clean:
	rm -f $(xdb_OBJECTS)
