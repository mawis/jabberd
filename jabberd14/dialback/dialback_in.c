/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "License").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the License.  You
 * may obtain a copy of the License at http://www.jabber.com/license/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2000 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * --------------------------------------------------------------------------*/

#include <jabberd.h>
#include "dialback.h"

dialback_in_read()
    if result, make a valid, set from=d->i->id, deliver it
    if packet, check in_ok hash for from/to key and make sure m==m

dialback_in_packets
    if route, get child and flag as invalid
    get mio from id hash (and remove from that has)
    put in valid hash
    send result

/* 
On incoming connections, it's our job to validate any packets we receive on this server

We'll get:
    <db:result to=B from=A>...</db:result>
We verify w/ the dialback process, then we'll send back:
    <db:result type="valid" to=A from=B/>

*/


/* callback for mio for accepted sockets that are dialback */
void dialback_in_read_db(mio s, int flags, void *arg, xmlnode x)
{
    miod md = (miod)arg;

    if(flags != MIO_XML_NODE) return;

    /* incoming verification request, check and respond */
    if(j_strcmp(xmlnode_get_name(x),"db:verify") == 0)
    {
        if(j_strcmp( xmlnode_get_data(x), _pthsock_server_merlin(xmlnode_pool(x), c->si->secret, xmlnode_get_attrib(x,"from"), xmlnode_get_attrib(x,"id"))) == 0)
            xmlnode_put_attrib(x,"type","valid");
        else
            xmlnode_put_attrib(x,"type","invalid");
        jutil_tofrom(x);
        mio_write(c->s, x, NULL, 0);
        return;
    }

    /* incoming result, make a host and forward on */
    if(j_strcmp(xmlnode_get_name(x),"db:result") == 0)
    {
        /* make a new host */
        h = pmalloco(c->p, sizeof(_host));
        h->type = htype_IN;
        h->si = c->si;
        h->c = c;
        h->id = jid_new(c->p,xmlnode_get_attrib(x,"to"));
        jid_set(h->id,xmlnode_get_attrib(x,"from"),JID_RESOURCE);
        jid_set(h->id,c->id,JID_USER); /* special user of the id attrib makes this key unique */
        ghash_put(c->si->hosts,jid_full(h->id),h); /* register us */
        pool_cleanup(c->p,_pthsock_server_host_cleanup,(void *)h); /* make sure things get put back to normal afterwards */

        /* send the verify back to them, on another outgoing trusted socket, via deliver (so it is real and goes through dnsrv and anything else) */
        x2 = xmlnode_new_tag_pool(xmlnode_pool(x),"db:verify");
        xmlnode_put_attrib(x2,"to",xmlnode_get_attrib(x,"from"));
        xmlnode_put_attrib(x2,"from",xmlnode_get_attrib(x,"to"));
        xmlnode_put_attrib(x2,"id",c->id);
        xmlnode_insert_node(x2,xmlnode_get_firstchild(x)); /* copy in any children */
        deliver(dpacket_new(x2),c->si->i);

        return;
    }

    /* hmm, incoming packet on dialback line, there better be a host for it or else! */
    to = jid_new(xmlnode_pool(x),xmlnode_get_attrib(x,"to"));
    from = jid_new(xmlnode_pool(x),xmlnode_get_attrib(x,"from"));
    if(to != NULL && from != NULL)
        h = ghash_get(c->si->hosts, spools(xmlnode_pool(x),c->id,"@",to->server,"/",from->server,xmlnode_pool(x)));
    if(h == NULL || !h->valid || h->c != c)
    { /* dude, what's your problem!  *click* */
        mio_write(c->s, NULL, "<stream:error>Invalid Packets Recieved!</stream:error>", -1);
        mio_close(c->s);
        xmlnode_free(x);
        break;
    }

    md->last = time(NULL);
    deliver(dpacket_new(x),d->i);
}


/* callback for mio for accepted sockets that are legacy */
void dialback_in_read_legacy(mio s, int flags, void *arg, xmlnode x)
{
    miod md = (miod)arg;

    if(flags != MIO_XML_NODE) return;

    md->last = time(NULL);
    deliver(dpacket_new(x),d->i);
}

/* callback for mio for accepted sockets */
void dialback_in_read(mio s, int flags, void *arg, xmlnode x)
{
    db d = (db)arg;
    xmlnode x2;
    jid to, from;

    if(flags == MIO_NEW)
    {
        log_debug(ZONE,"NEW incoming server socket connected at %d",s->fd);
        c = pmalloco(s->p, sizeof(_conn)); /* we get free'd with the socket */
        c->s = s;
        c->p = s->p;
        c->si = (ssi)arg; /* old arg is si */
        mio_reset(s, pthsock_server_inread, (void*)c);
        return;
    }

    if(flags == MIO_XML_ROOT)
    {
        /* new incoming connection sent a header, write our header */
        x2 = xstream_header("jabber:server", NULL, xmlnode_get_attrib(x,"to"));
        xmlnode_put_attrib(x2,"xmlns:db","jabber:server:dialback"); /* flag ourselves as dialback capable */
        c->id = pstrdup(c->p,_pthsock_server_randstr());
        xmlnode_put_attrib(x2,"id",c->id); /* send random id as a challenge */
        mio_write(c->s,NULL, xstream_header_char(x2), -1);
        xmlnode_free(x2);

        /* validate namespace */
        if(j_strcmp(xmlnode_get_attrib(x,"xmlns"),"jabber:server") != 0)
        {
            mio_write(c->s, NULL, "<stream:error>Invalid Stream Header!</stream:error>", -1);
            mio_close(c->s);
            xmlnode_free(x);
            return;
        }

        if(xmlnode_get_attrib(x,"xmlns:db") == NULL)
        {
            if(c->si->legacy)
            {
                c->legacy = 1;
                log_notice(xmlnode_get_attrib(x,"to"),"legacy server incoming connection established from %s",c->s->ip);
            }else{
                mio_write(c->s, NULL, "<stream:error>Legacy Access Denied!</stream:error>", -1);
                mio_close(c->s);
                xmlnode_free(x);
                return;
            }
        }

        xmlnode_free(x);
    }
}

void dialback_in_packet(db d, xmlnode x)
{
    /* if the route packet we generated failed, we get routed errors too */
    if(j_strcmp(xmlnode_get_name(x),"route") == 0)
    {
    }

    if route, get child and flag as invalid
    get mio from id hash (and remove from that has)
    put in valid hash
    send result

}