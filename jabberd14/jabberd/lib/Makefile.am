noinst_LTLIBRARIES = libjabberdlib.la

include_HEADERS = base64.hh crc32.hh expat.hh hash.hh hmac.hh jabberid.hh jabberdlib.h jid.hh jpacket.hh jutil.hh karma.hh lwresc.hh pool.hh

libjabberdlib_la_SOURCES = base64.cc karma.cc xhash.cc crc32.cc jid.cc jabberid.cc pool.cc expat.cc jpacket.cc socket.cc jutil.cc rate.cc str.cc xstream.cc hash.cc hmac.cc messages.cc xmlnode.cc lwresc.cc
libjabberdlib_la_LDFLAGS = @LDFLAGS@
INCLUDES = -I..
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@
