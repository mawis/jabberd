noinst_LTLIBRARIES = libjabberdlib.la

include_HEADERS = jabberdlib.h

libjabberdlib_la_SOURCES = base64.c karma.c sha.c xhash.c crc32.c jid.c pool.c snprintf.c xmlnode.c expat.c jpacket.c socket.c jutil.c rate.c str.c xstream.c hmac.c messages.cc
libjabberdlib_la_LDFLAGS = @LDFLAGS@ -version-info 1:0:0
INCLUDES = -I..
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@
