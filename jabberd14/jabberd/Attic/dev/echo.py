#!/usr/bin/env python

from sys import *
import getopt, string
import UserDict
from jpy import Judo, Jabber

class ArgsTable(UserDict.UserDict):
    def __init__(self, args, options):
        UserDict.UserDict.__init__(self)
        # Parse out options
        opt, flags = getopt.getopt(args, '', options)
        # Load parsed data into hash table
        for (i, j) in opt:
            self[i[2:]] = j
        for i in flags:
            self[i] = ''
        

class EchoStream(Judo.TagStream):
    def __init__(self, id, dropFlag):
        Judo.TagStream.__init__(self)
        self.id = id
        self.dropFlag = dropFlag
        
    def on_Tag(self, tag):
        # Echo the tag to stderr..
        stderr.write(">> %s: %s\n" % (self.id, tag.toXML()))
        # Echo the tag if necessary
        if not self.dropFlag:
            # Replace the "to" attribute with the "from" attribute
            tag.swapAttribs("to", "from")
            # Echo the tag to the sender
            self.write(tag.toXML())

    def waitForTag(self):
        s = stdin.readline()
        if (len(s) > 0):
            self.feed(s)
            return 1
        return 0

    def write(self, buf):
        stderr.write("<< %s: %s\n" % (self.id, buf))
        stdout.write(buf)
        stdout.flush()


if __name__ == "__main__":
    # Parse command line arguments
    a = ArgsTable(argv[1:], [ 'id=', 'drop'])

    if not a.has_key("id"):
        stderr.write("Echo.py error: You must provide at least an ID for this component.\n")
        exit(-1)
        
    # Create the echo stream handler & send the <root> tag
    es = EchoStream(a["id"], a.has_key("drop"))
    es.write("<root>")

    # Begin handling incoming packets
    while (es.waitForTag()):
        pass
    stderr.write("Done for %s\n" % (a["id"]))


