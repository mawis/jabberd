all: pthsock_client pthsock_server

pthsock_client:
	gcc -fPIC -shared -o pthsock_client.so pthsock_client.c -I../jabberd

pthsock_server:
	gcc -fPIC -shared -o pthsock_server.so pthsock_server.c -I../jabberd

clean:
	rm -f pthsock_client.so pthsock_server.so
