all: xdb_file pthsock_client

xdb_file:
	gcc -fPIC -shared -o xdb_file.so xdb_file.c -I../src

pthsock_client:
	gcc -fPIC -shared -o pthsock_client.so pthsock_client.c -I../src

clean:
	rm xdb_file.so pthsock_client.so
