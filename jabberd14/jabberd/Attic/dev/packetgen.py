#!/usr/bin/env python

import echo
import time

dest_host = "foo.org"

if __name__ == "__main__":
    try:
        # Create an echo stream
        es = echo.EchoStream("PacketGen", 0)
        es.write("<root>")
        
        # simple_svc
        es.write("<message to='%s'/>" % (dest_host))
        
        # simple_xdb
        es.write("<xdb to='%s'/>" % (dest_host))
        
        # simple_log
        es.write("<log to='%s'/>" % (dest_host))
        
        # ns_filter_xdb
        es.write("<log to='%s' xmlns='xdb:test'/>" % (dest_host))
        
        # Delay so user can examine results
        time.sleep(60)
    except:
        pass
