include ../platform-settings

CFLAGS=$(CCFLAGS) -I../jabberd

xdb_file_OBJECTS= xdb_file.o

ifeq ($(__CYGWIN__),1)
xdb_file_OBJECTS+= ../cygwin/dllinit.o
endif

single: static

all: xdb_file

xdb_file: $(xdb_file_OBJECTS)
ifeq ($(__CYGWIN__),1)
# Make .def file:
	echo EXPORTS > xdb_file.def
	nm $(xdb_file_OBJECTS) $(PTHLIB) | grep '^........ [T] _' | sed 's/[^_]*_//' | sort >> xdb_file.def
	dllwrap --def xdb_file.def --driver-name $(CC) -o xdb_file.dll $(xdb_file_OBJECTS) ../jabberd/jabberd.a $(LDFLAGS) $(LIBS)
else
	$(CC) $(CFLAGS) $(MCFLAGS) -o xdb_file.so $(xdb_file_OBJECTS) $(LDFLAGS) $(LIBS)
endif

static: $(xdb_file_OBJECTS)

clean:
ifeq ($(__CYGWIN__),1)
	rm -f $(xdb_file_OBJECTS) xdb_file.dll *.a *.def *.exp
else
	rm -f $(xdb_file_OBJECTS) xdb_file.so
endif
