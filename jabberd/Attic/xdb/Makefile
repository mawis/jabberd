CC=gcc
DEFINES=-DCONFIGXML="\"jabber.xml\""
CFLAGS=-fPIC -g $(DEFINES) -I./ -I../ `libxode-config --cflags` -Wall

xdb_OBJECTS=base_ns.o

all: $(xdb_OBJECTS)

clean:
	rm -f $(xdb_OBJECTS)
