#!/usr/bin/env python

import echo
import time

dest_host = "foo.org"
origin_host = "bar.org"

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
        es.write("<log to='%s'>Hello, world</log>" % (dest_host))
        
        # ns_filter_xdb
        es.write("<xdb to='%s/xdb:test'/>" % (dest_host))

        # ns2_filter_xdb
        es.write("<xdb to='%s/xdb:test2'/>" % (dest_host))

        # ns3_filter_xdb
        es.write("<xdb to='%s/xdb:test3'/>" % (dest_host))

        # ns4_filter_xdb
        es.write("<xdb to='foobar.org'/>")

        # Delay so user can examine results
        time.sleep(60)
    except:
        pass
