CC=gcc
CFLAGS=-fPIC -shared -g $(DEFINES) -I./ -I../ -I../jabberd `libxode-config --cflags` `jabber-config --cflags` -Wall
LDFLAGS=`libxode-config --ldflags` `libxode-config --libs` `pth-config --libs --ldflags` `jabber-config --ldflags` `jabber-config --libs` -ldl

xdb_file_OBJECTS=xdb_file.o

all: xdb_file

xdb_file: $(xdb_file_OBJECTS)
	$(CC) $(CFLAGS) -o xdb_file.so $(xdb_file_OBJECTS) $(LDFLAGS)

clean:
	rm -f $(xdb_file_OBJECTS) xdb_file.so
