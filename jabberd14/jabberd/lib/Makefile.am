noinst_LTLIBRARIES = libjabberdlib.la

include_HEADERS = jabberdlib.h

libjabberdlib_la_SOURCES = base64.cc karma.cc xhash.cc crc32.cc jid.cc pool.cc expat.cc jpacket.cc socket.cc jutil.cc rate.cc str.cc xstream.cc hash.cc hmac.cc messages.cc xmlnode.cc
libjabberdlib_la_LDFLAGS = @LDFLAGS@ -version-info 1:0:0
INCLUDES = -I..
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@
