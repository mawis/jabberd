CFLAGS=-fPIC -g $(DEFINES) -I./ -I../ -I../jabberd `libxode-config --cflags` `jabber-config --cflags` -Wall
LDFLAGS=`libxode-config --ldflags --libs` `pth-config --libs --ldflags` `jabber-config --ldflags --libs` -ldl

all: xdb_file

xdb_file:
	gcc -fPIC -shared -o xdb_file.so xdb_file.c $(CFLAGS) $(LDFLAGS)

clean:
	rm -f xdb_file.so
