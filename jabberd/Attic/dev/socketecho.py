#!/usr/bin/env python

from sys import *
from jpy import Judo, Jabber

# Echo server program
from socket import *
HOST = '127.0.0.1'        # Symbolic name meaning the local host
PORT = 50000              # Arbitrary non-privileged server

# SocketEchoStream
class SocketEchoStream(Judo.TagStream):
    def __init__(self, socket):
        Judo.TagStream.__init__(self)
        self.socket = socket
        # Transmit root element
        self.socket.send("<root id='52'>")

    def on_Tag(self, tag):
        # Echo the tag to the console
        print ">> %s\n" % (tag.toXML())
        # If this is a handshake request, automatically
        # permit
        if (tag.name == "handshake"):
            self.socket.send("<handshake/>")
        # Otherwise, swap to/from and echo back
        else:
            tag.swapAttribs("to", "from")
            self.socket.send(tag.toXML())
            print("<< %s\n" % (tag.toXML()))
            

if __name__ == "__main__":
        # Create a server socket
        s = socket(AF_INET, SOCK_STREAM)
        s.bind(HOST, PORT)
        s.listen(1)
        
        # Accept incoming client...
        conn, addr = s.accept()
        try:
            print 'Connected by', addr        
            # Setup a socket echo stream
            ts = SocketEchoStream(conn)
            while (1):
                data = conn.recv(1024)
                print "Got: %s" % (data)
                if not data: break
                ts.feed(data)
        finally:
            # Close the connection
            conn.shutdown(2)
            s.shutdown(2)
