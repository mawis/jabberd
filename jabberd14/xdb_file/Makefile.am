lib_LTLIBRARIES = libjabberdxdbfile.la
bin_PROGRAMS = xdbfiletool

libjabberdxdbfile_la_SOURCES = xdb_file.cc
libjabberdxdbfile_la_LIBADD = $(top_builddir)/jabberd/libjabberd.la
libjabberdxdbfile_la_LDFLAGS = @LDFLAGS@ @VERSION_INFO@ -module -version-info 2:0:0

xdbfiletool_SOURCES = xdbfiletool.cc
xdbfiletool_LDADD = $(top_builddir)/jabberd/libjabberd.la \
		    -lpopt
xdbfiletool_LDFLAGS = @LDFLAGS@

INCLUDES = -I../jabberd -I../jabberd/lib
