include ../platform-settings

CFLAGS:=$(CFLAGS) -I../jabberd

dialback_OBJECTS=dialback.o dialback_in.o dialback_out.o

all: dialback

dialback: $(dialback_OBJECTS)
	$(CC) $(CFLAGS) $(MCFLAGS) -o dialback.so $(dialback_OBJECTS) $(LDFLAGS) $(LIBS)

static: $(dialback_OBJECTS)

single: $(dialback_OBJECTS)

clean:
	rm -f $(dialback_OBJECTS) dialback.so
