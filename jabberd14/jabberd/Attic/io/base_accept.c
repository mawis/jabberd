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
 
#include "jabberd.h"

#define A_ERROR  -1
#define A_DUPLEX  0
#define A_SIMPLEX 1
#define A_READY   2

typedef struct accept_listener_st
{
    pool         p;
    char*        keybuf;
    char*        ip;
    unsigned int port;
    xmlnode      hosts;
} _accept_listener, *accept_listener;

typedef struct accept_instance_queue_st
{
    pth_message_t head;
    xmlnode     x;
} *accept_instance_queue, _accept_instance_queue;

typedef struct accept_io_st
{
    pool            p;
    mio             io;
    int             state;
    char*           id;
    struct accept_instance_st *instance;
} *accept_io, _accept_io;;

typedef struct accept_instance_st
{
    pool        p;
    accept_io   aio;
    instance    inst;
    char*       secret;
    pth_msgport_t write_queue;
} *accept_instance, _accept_instance;

/* Write packets to a xmlio object */
result base_accept_deliver(instance i, dpacket p, void* arg)
{
    accept_instance ai = (accept_instance)arg;

    /* Insert the message into the write_queue if we don't
       have a MIO socket yet.. */
    if (ai->aio == NULL)
    {
	    accept_instance_queue entry = pmalloco(p->p, sizeof(_accept_instance_queue));
	    entry->x = p->x;
	    pth_msgport_put(ai->write_queue, (pth_message_t*)entry);
    }
    /* Otherwise, write directly to the MIO socket */
    else
    {
	    mio_write(ai->aio->io, p->x, NULL, 0);
    }
    return r_DONE;
}


/* Handle incoming packets from the xstream associated with an MIO object */
void base_accept_process_xml(mio m, int state, void* arg, xmlnode x)
{
    accept_io aio;
    int astate;
    xmlnode cur;

    log_debug(ZONE, "process XML: m:%X state:%d, arg:%X, x:%X", m, state, arg, x);

    switch(state)
    {
        case MIO_XML_ROOT:
        {
	        char* block;

	        /* The default argument for this callback is an accept_listener struct, 
	        inherited from the parent MIO object */
	        accept_listener al = (accept_listener)arg;
	        accept_instance ai = NULL;

    log_debug(ZONE, "MIO_XML_ROOTL: m:%X state:%d, arg:%X, x:%X", m, state, arg, x);
	        /* Ensure request namespace is correct... */
	        if (j_strcmp(xmlnode_get_attrib(x, "xmlns"), "jabber:component:accept") != 0)
	        {
	            /* Log that the connected component sent an invalid namespace */
	            log_warn("base_accept_undetermined", "Recv'd invalid namespace. Closing connection.");
	            /* Notify component with stream:error */
	            mio_write(m, NULL, SERROR_NAMESPACE, strlen(SERROR_NAMESPACE));
	            /* Close the socket and cleanup */
	            mio_close(m);
	            xmlnode_free(x);
	            return;
	        }
	        /* Search the acceptor hosts node for a host which matches the "to" attribute sent in the
	        stream header */
	        if((ai = xmlnode_get_vattrib(al->hosts, xmlnode_get_attrib(x, "to"))))
	        {
	           astate = A_DUPLEX;
	        }
	        /* If no instance was found that matches on the "to" attribute, examine the "from" attribute
	        instead -- this signals that this incoming connection is not interested in recv'ing packets;
	        it only wants to send packets */
	        else if((ai = xmlnode_get_vattrib(al->hosts, xmlnode_get_attrib(x, "from"))))
	        {
	           astate = A_SIMPLEX;
	        }
	        /* If no instance was found at all, log an error and disconnect the socket */
	        else
	        {
	            /* Log that a socket requested an invalide hostname */
	            log_warn("base_accept_undetermined", "Request for invalid host: %s", xmlnode_get_attrib(x, "to"));
	            /* Notify socket with stream:error */
	            mio_write(m, NULL, SERROR_INVALIDHOST, strlen(SERROR_INVALIDHOST));
	            /* Close the socket and cleanup */
	            mio_close(m);
	            xmlnode_free(x);
	            return;
	        }
	        /* A matching instance was found, create an accept_io object wrapper for
	        this MIO object and reset the callback so that next time the argument
	        is an accept_io object */
	        aio           = pmalloco(m->p, sizeof(_accept_io));
	        aio->p        = m->p;
	        aio->state    = astate;
	        aio->io       = m;
	        aio->instance = ai;
	        mio_reset(m, (void*)base_accept_process_xml, aio);

	        /* Send header w/ proper namespace, using instance i */
	        cur = xstream_header("jabber:component:accept", NULL, NULL);
	        /* Save stream ID for auth'ing later */
	        aio->id = pstrdup(aio->p, xmlnode_get_attrib(cur, "id"));
	        /* Transmit stream header */
	        block = xstream_header_char(cur);
	        log_debug(ZONE, "base_accept socket connected; sending header: %s", block);
	        mio_write(m, NULL, block, strlen(block));
	   
	        /* Cleanup */
	        xmlnode_free(cur);
	        xmlnode_free(x);
	        break;
        }
        case MIO_XML_NODE:
        {
	        accept_io aio = (accept_io)arg;
	        log_debug(ZONE, "base_accept: %s", xmlnode2str(x));	

    log_debug(ZONE, "MIO_XML_NODE: m:%X state:%d, arg:%X, x:%X", m, state, arg, x);
	        /* If aio has been authenticated previously, go ahead
	        and deliver the packet */
	        if(aio->state == A_READY)
	        {
	            /* Hide 1.0 style transports etherx:* attribs */
	            xmlnode_hide_attrib(x, "etherx:to");
	            xmlnode_hide_attrib(x, "etherx:from");
	            deliver(dpacket_new(x), aio->instance->inst);
	            return;
	        }
	        /* If this is a handshake packet, attempt to auth the socket... */
	        if(j_strcmp(xmlnode_get_name(x), "handshake") == 0)
	        {
	            char* block = NULL;
	            char  hashbuf[41];
	    
	            /* Merge SID and password together */
	            block = spools(xmlnode_pool(x), aio->id, aio->instance->secret, xmlnode_pool(x));
	            /* Create a SHA hash of this instance's password & SID */
	            shahash_r(block, hashbuf);
	            /* Check the <handshake> against the calculated hash */
	            log_debug(ZONE, "Checking: \n%s\n%s", hashbuf, xmlnode_get_data(x));
	            if(j_strcmp(hashbuf, xmlnode_get_data(x)) == 0)
	            {
		            /* Send a handshake confirmation */
		            mio_write(aio->io, NULL, "<handshake/>", 12);
		            /* If this is a duplex socket, the previous connection
		            should be replaced by this connect (if necessary) */
		            if(aio->state == A_DUPLEX)
		            {
		                accept_instance_queue entry;
		        
		                /* If an existing duplex AIO is attached to this instance,
		                we need to "take over" the instance and deal with it's 
		                queue directly */
		                if(aio->instance->aio != NULL)
		                {
			                accept_io oldaio = aio->instance->aio;
			                log_warn(oldaio->id, "Socket override by another component");
			                /* Hijack the instance, making aio the default I/O interface */
			                aio->instance->aio = aio;
			                /* Close the existing aio object */
			                mio_write(oldaio->io, NULL, "<stream:error>Socket override by another component.</stream:error></stream:stream>", 81);
			                mio_close(oldaio->io);
		                }
		                else
		                {
			                aio->instance->aio = aio;
		                }
		                /* Flush the queue of messages stored by the instance */
		                entry = (accept_instance_queue) pth_msgport_get(aio->instance->write_queue);
		                while(entry != NULL)
		                {
			                mio_write(aio->io, entry->x, NULL, 0);
		                }
		    
		            }
		            /* Set the AIO state to READY */
		            aio->state = A_READY;
	            }
	            /* Handshake failed */
	            else
	            {
		            mio_write(aio->io, NULL, "<stream:error>Invalid handshake</stream:error>", 46);
		            mio_close(aio->io);
	            }
	        }
	        /* Unauthorized packet since no authentication has been performed */
	        else
	        {
	            mio_write(aio->io, NULL, "<stream:error>Must send handshake first.</stream:error>", 54);
	            mio_close(aio->io);
	        }
	        xmlnode_free(x);
	        break;
        }
        case MIO_XML_ERROR:
        {
	        accept_io aio = (accept_io)arg;
	    
    log_debug(ZONE, "MIO_XML_ERR: m:%X state:%d, arg:%X, x:%X", m, state, arg, x);
	        /* Transmit a parse error */
	        mio_write(aio->io, NULL, "<stream:error>Invalid XML</stream:error>", 39);

	        break;
        }
        case MIO_XML_CLOSE:
        {
	        accept_io aio = (accept_io)arg;

    log_debug(ZONE, "MIO_XML_CLOSE: m:%X state:%d, arg:%X, x:%X", m, state, arg, x);
	        /* Close the stream */
	        mio_write(aio->io, NULL, "</stream:stream>", 16);
	        mio_close(aio->io);

	        break;
        }
        case MIO_CLOSED:
        {
	        accept_io aio = (accept_io)arg;

    log_debug(ZONE, "MIO_CLOSED: m:%X state:%d, arg:%X, x:%X", m, state, arg, x);
	        /* Bounce the current packet */
	        deliver_fail(dpacket_new(x), "External Server Error");

	        /* If this AIO object is the default IO object for an instance,
	        make sure that the instance is notified that the AIO object
	        is leaving */
	        if((aio->instance != NULL) && (aio->instance->aio == aio))
	            aio->instance->aio = NULL;
        }
    }
}

/* A global hash table keyed by ip:port string, with xmlnode
 * values that store an vattrib list of instance id->sinks */
HASHTABLE G_listeners            = NULL;
pool      G_pool                 = NULL;

void base_accept_listener_cleanup(void *arg)
{
    accept_listener al = (accept_listener)arg;
    ghash_remove(G_listeners, al->keybuf);
}

result base_accept_config(instance id, xmlnode x, void *arg)
{
    char *port   = xmlnode_get_data(xmlnode_get_tag(x, "port"));
    char *ip     = xmlnode_get_data(xmlnode_get_tag(x, "ip"));
    char *secret = xmlnode_get_data(xmlnode_get_tag(x, "secret"));
	char *keybuf[24];
    accept_instance inst;
    xmlnode cur;

    if(id == NULL)
    {
        log_debug(ZONE,"base_accept_config validating configuration");
		if ((xmlnode_get_tag(x, "ip") == NULL) || 
		    (xmlnode_get_tag(x, "port") == NULL) || 
		    (xmlnode_get_tag(x,"secret") == NULL))
        {			
            xmlnode_put_attrib(x,"error","<accept> requires the following subtags: <ip>, <port>, and <secret>");
            return r_ERR;
        }		
        return r_PASS;
    }

	/* Setup global hash of ip:port->xmlnode */
    if(G_listeners == NULL)
	    G_listeners = ghash_create(25, (KEYHASHFUNC)str_hash_code, (KEYCOMPAREFUNC)j_strcmp);

	/* Setup global memory pool for misc allocs */
    if(G_pool == NULL)
	    G_pool = pool_new();


    log_debug(ZONE,"base_accept_config performing configuration %s\n",xmlnode2str(x));

	/* Format ip:port into a string */
	snprintf((char*)&keybuf, 22, "%s:%s", ip, port);

	/* Look for an existing xmlnode entry which uses the requested IP and port */
	cur = ghash_get(G_listeners, keybuf); 

    /* If no matching entry was found, create a new one for this
	 * instance and start a new listening thread */
	if(cur == NULL)
    {
		accept_listener al;
        pool p = pool_new(); 
		
		/* Create a new host tag */
		cur = xmlnode_new_tag_pool(G_pool,"host");

		/* Insert ip:port->cur into hashtable */
		ghash_put(G_listeners, pstrdup(G_pool, (char*)&keybuf), cur);

        xmlnode_put_attrib(x, "keybuf", (char*)&keybuf);

		/* Create a listen struct to pass info to the listen thread */
		al         = pmalloco(p, sizeof(_accept_listener));
        al->p      = p;
        al->keybuf = pstrdup(p, (char*)&keybuf);
		al->ip     = ip;
		al->port   = atoi(port);
		al->hosts  = cur;

        pool_cleanup(id->p, base_accept_listener_cleanup, (void*)al);
		
        /* Start a new listening thread and associate this <listen> tag with it */
        mio_listen_xml(j_atoi(port, 0), ip, base_accept_process_xml, (void*)al);
    }

	/* Setup the default sink for this instance */ 
    inst            = pmalloco(id->p, sizeof(_accept_instance));
    inst->p    = id->p;
	inst->inst = id;
    inst->secret = secret;
    inst->write_queue = pth_msgport_create("bainste_accept");

    log_debug(ZONE,"new listening instance created %X",inst);

    /* Store a pointer to the instance as a vattrib in the 
       listener's "hosts" node */
    xmlnode_put_vattrib(cur, id->id, (void*)inst);

	/* Register a packet handler and cleanup heartbeat for this instance */
    register_phandler(id, o_DELIVER, base_accept_deliver, (void *)inst);

    return r_DONE;
}


void base_accept(void)
{
    log_debug(ZONE,"base_accept loading...\n");
    register_config("accept",base_accept_config,NULL);
}
