all: xdb_file

xdb_file:
	gcc -fPIC -shared -o xdb_file.so xdb_file.c -I../jabberd

clean:
	rm -f xdb_file.so
