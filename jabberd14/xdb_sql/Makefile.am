lib_LTLIBRARIES = libjabberdxdbsql.la

libjabberdxdbsql_la_SOURCES = xdb_sql.cc
libjabberdxdbsql_la_LIBADD = $(top_builddir)/jabberd/libjabberd.la
libjabberdxdbsql_la_LDFLAGS = @LDFLAGS@ @VERSION_INFO@ -module -version-info 2:0:0

INCLUDES = -I../jabberd -I../jabberd/lib
