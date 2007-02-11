noinst_LTLIBRARIES = libjabberdlib.la

include_HEADERS = jabberdlib.h

libjabberdlib_la_SOURCES = base64.c karma.c xhash.c crc32.c jid.c pool.c expat.c jpacket.c socket.c jutil.c rate.c str.c xstream.c hash.cc hmac.cc messages.cc xmlnode.cc
libjabberdlib_la_LDFLAGS = @LDFLAGS@ -version-info 1:0:0
INCLUDES = -I..
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@
