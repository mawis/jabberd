lib_LTLIBRARIES = libjabberdxdbfile.la
bin_PROGRAMS = xdbfiletool

include_HEADERS = jabberdxdbfile.h

libjabberdxdbfile_la_SOURCES = xdb_file.c
libjabberdxdbfile_la_LIBADD = @LDFLAGS@ $(top_builddir)/jabberd/libjabberd.la

xdbfiletool_SOURCES = xdbfiletool.c
xdbfiletool_LDADD = $(top_builddir)/jabberd/libjabberd.la \
		    $(top_builddir)/xdb_file/libjabberdxdbfile.la

INCLUDES = -I../jabberd -I../jabberd/lib
