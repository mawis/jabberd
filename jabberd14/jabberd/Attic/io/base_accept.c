/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  Jabber
 *  Copyright (C) 1998-1999 The Jabber Team http://jabber.org/
 */

#include "jabberd.h"

/* how many seconds until packets begin to "bounce" that should be delivered */
#define ACCEPT_PACKET_TIMEOUT 30
/* how many seconds a socket has to send a valid handshake */
#define ACCEPT_HANDSHAKE_TIMEOUT 5
/* the arg to the listen() call */
#define ACCEPT_LISTEN_BACKLOG 10

/* base_accept
 * 
 * Notes:
 * 	Each base_accept instance checks a global list of base_accept instances to see if
 * 	it can share a listening socket thread with other instances. By sharing a listening
 * 	socket among instances, multiple transports can be accepted via a single socket --
 * 	distingushing which instance to associate the socket with is done by examining the
 * 	<stream:stream> "to" attribute.
 *
 * 	Sink: each instance registered with base_accept has a "sink" -- this is basically
 * 	just a simple wrapper around a thread-safe queue for incoming dpackets to be stored
 * 	in.
 *
 * 	Acceptor: each socket accepted by the listening socket is associated with an acceptor
 * 	that tracks the events and state of the socket. Once a socket is identified as belonging
 * 	to a particular instance, the acceptor is given a pointer to the corresponding sink.
 * 	
 * 	*/

/*
how does this mess work... hmmm...

the accept section lives in an instance
it can share an ip/port w/ another section, but the secret must be unique,
so it either finds an existing listen thread and adds it's secret and instance pair to it,
or starts a new listen thread
and each section registers a "default" sink packet handler
when new connections come in, a read and write thread are started to deal with it
if a valid handshake is negotiated, the write thread starts to pull packets from the default sink handler
if the default sink is already in use by another write thread, another sink packet handler is registered
when the write threads exit, only the default sink would persist, others all r_UNREG

the handshake is:
<handshake host="1234.foo.jabber.org">SHAHASH of id+secret</handshake>
the host attrib is optional, and when used causes a new sink/handler to be registerd in the o_PREDELIVER stage to "hijack" packets to that host
note: the use of the host attrib and <host> element in the config are not automagically paired, must be done by the administrator configuring jabberd and whatever app is using the socket
also, set host="void" to disable any packets or data being written to the socket

<accept>
  <ip>1.2.3.4</ip>
  <port>2020</port>
  <secret>foobar</secret>
</accept>

*/

/* Prototypes for structs */
typedef struct sink_struct  *sink, _sink;
typedef struct acceptor_struct *acceptor, _acceptor;

/* Listen struct -- information about a listening socket */
typedef struct
{
	char*        ip;
	unsigned int port;
	xmlnode      hosts;
} *listen_info, _listen_info;

/* simple wrapper around the pth messages to pass packets */
typedef struct
{
    pth_message_t head; /* the standard pth message header */
    dpacket p;
} *drop, _drop;

/* simple wrapper around pth message ports, so we could use something else in the future easily */
struct sink_struct
{
	pool     p;
    instance i;
	acceptor a;     /* Reference to the acceptor(socket) that this sink is currently attached to */
    pth_msgport_t mp;
    time_t last;
	char* secret;   /* Shortcut pointer to the secret passphrase */
};

/* data shared for handlers related to a connection */
struct acceptor_struct
{
	pool p;
	sink s;	           /* Sink associated with this socket (init'd after auth) */
    int sock;
	int state;         /* State of the acceptor: error(-1), duplex (0), simplex(1) */
    char *id;
    xmlnode hosts;     /* A list of hosts w/ sinks as vattribs, keyed by instance->id */
    pth_event_t emp;   /* Message port (write_queue) event */
	pth_event_t eread; /* Data available on socket event */
	pth_event_t etime; /* Data timeout event */
	pth_event_t ering;
};

#define A_ERROR  -1
#define A_DUPLEX  0
#define A_SIMPLEX 1


/* write packets to sink */
result base_accept_phandler(instance i, dpacket p, void *arg)
{
    sink s = (sink)arg;
    drop d;

    d = pmalloco(p->p, sizeof(_drop));
    d->p = p;

    pth_msgport_put(s->mp, (pth_message_t *)d);

    return r_DONE;
}

void base_accept_read_packets(int type, xmlnode x, void *arg)
{
    acceptor a = (acceptor)arg;
    xmlnode cur = NULL;
    char *block;
    sink snew;
	char hashbuf[41];

	
    switch(type)
    {
    case XSTREAM_ROOT:
        /* Ensure requested namespace is correct.. */
        if (j_strcmp(xmlnode_get_attrib(x, "xmlns"), "jabber:component:accept") != 0)
        {
                /* Log that this component sent an invalid namespace */
                log_alert("base_accept_undetermined", "Recv'd invalid namespace. Closing connection.");
                /* Notify component with stream:error */
                pth_write(a->sock, SERROR_NAMESPACE, strlen(SERROR_NAMESPACE));
                /* Set status code and return */
				a->state = A_ERROR;
        }
		else 
		{
			/* Search the acceptor hosts node for a host which matches the "to" attribute sent in the
			 * stream header */
			a->state = A_DUPLEX;
			snew = xmlnode_get_vattrib(a->hosts, xmlnode_get_attrib(x, "to"));
			/* If no sink was found that matches on the "to" header, examine the "from" header 
			 * instead -- this signals that this incoming connection is not interested in recv'ing
			 * packets, just in sending them. */
			if (snew == NULL)
			{
				snew = xmlnode_get_vattrib(a->hosts, xmlnode_get_attrib(x, "from"));
				a->state = A_SIMPLEX;
			}
			/* If no sink was found at all, log an error and disconnect the socket */
			if (snew == NULL) 
			{
				/* Log that a socket requested an invalid hostname */
				log_error("base_accept_undetermined", "Request for invalid host: %s", xmlnode_get_attrib(x, "to"));
				/* Notify socket with stream:error */
				pth_write(a->sock, SERROR_INVALIDHOST, strlen(SERROR_INVALIDHOST));
				/* Set status code and return */
				a->state = A_ERROR;
			}
			else
			{
				/* Associate the acceptor with a sink */
				a->s = snew;
				/* Send header w/ proper namespace, using instance i*/
				cur = xstream_header("jabber:component:accept",NULL,NULL);
				/* Save stream ID for auth'ing later */
				a->id = pstrdup(a->p,xmlnode_get_attrib(cur,"id"));
				block = xstream_header_char(cur);
				log_debug(ZONE,"socket connected, sending xstream header: %s",block);
				pth_write(a->sock,block,strlen(block));
			}
		}
        xmlnode_free(cur);
        xmlnode_free(x);
        break;
    case XSTREAM_NODE:
        log_debug(ZONE,"base_accept: %s",xmlnode2str(x));

		/* If this a duplex acceptor (transmit/recv) and we have a message queue event
		 * setup, go ahead and deliver the the packet directly */
        if ((a->state == A_DUPLEX) && (a->emp != NULL))
        {
            deliver(dpacket_new(x), a->s->i);
            return;
        }

		/* If this is a handshake packet, attempt to auth the socket.. */
		if (j_strcmp(xmlnode_get_name(x),"handshake") == 0)
		{
			/* Merge SID and passwd together */
		 	block = spools(xmlnode_pool(x), a->id, a->s->secret, xmlnode_pool(x));
			/* Create a SHA hash of this instance's passwd & sid */
			shahash_r(block, hashbuf);
			/* Check <handshake> against this instance's passwd */
			log_debug(ZONE, "Checking: \n%s\n%s", hashbuf, xmlnode_get_data(x));
			if (j_strcmp(hashbuf, xmlnode_get_data(x)) == 0)
			{
				pth_write(a->sock, "<handshake/>", 12);
				/* If this is a duplex socket, we need to hook up events
				 * and kick off a previous connection (if necessary) */
				if (a->state == A_DUPLEX)
				{
					/* If an existing duplex socket is using this message
					 * port, then we need to kick it off and take the message
					 * port for ourselves. */
					if (a->s->a != NULL)
					{
						acceptor olda = a->s->a;
						log_warn(olda->id, "Socket override by another component");
						/* Set the status on the existing acceptor */
						olda->state = A_ERROR;
						/* Set the sink's acceptor to ourselves (hijack it) */
						a->s->a = a;
						/* Notify the current acceptor for this sink that it's about
						 * to get shutdown */
						pth_write(olda->sock, "<stream:error>Socket override by another component.</stream:error></stream:stream>", 81);
					}
					else
					{
						a->s->a = a;
					}
					/* Hook up the message port events */
					a->emp = pth_event(PTH_EVENT_MSG,a->s->mp);
					if(a->etime != NULL)
						pth_event_free(a->etime, PTH_FREE_THIS);
					a->ering = pth_event_concat(a->eread, a->emp, NULL);
				}
				else if (a->state == A_SIMPLEX)
				{
					/* Simply disable the timer event and reset events */
					if (a->etime != NULL)
						pth_event_free(a->etime, PTH_FREE_THIS);
					a->ering = pth_event_concat(a->eread, NULL);
				}
			}
			/* Handshake failed */
			else
			{   
				pth_write(a->sock,"<stream:error>Invalid Handshake</stream:error>",46);
				a->state = A_ERROR;
			}
		}
		/* Otherwise, send an error and close the socket */
		else
		{
			pth_write(a->sock,"<stream:error>Must send handshake first</stream:error>",54);
			a->state = A_ERROR;
		}
		xmlnode_free(x);
		break;
		
    default:
        xmlnode_free(x);
        break;
    }
		
}

/* A thread proc for handling IO on a socket */
void *base_accept_io(void *arg)
{
    acceptor a = (acceptor)arg;
    xstream xs;
    int len;
    char buff[1024], *block;
    dpacket p = NULL;
    drop d;

    log_debug(ZONE,"io thread starting for %d",a->sock);

	/* Setup a new xstream for this socket */
    xs = xstream_new(a->p, base_accept_read_packets, arg);
    a->eread = pth_event(PTH_EVENT_FD|PTH_UNTIL_FD_READABLE,a->sock);
    a->etime = pth_event(PTH_EVENT_TIME, pth_timeout(ACCEPT_HANDSHAKE_TIMEOUT,0));
    a->ering = pth_event_concat(a->eread, a->etime, NULL);

    /* spin waiting on data from the socket, feeding to xstream */
    while(pth_wait(a->ering) > 0)
    {
		/* See if the state has changed on this acceptor -- if so
		 * the acceptor thread needs to exit as another primary
		 * instance handler has taken over */
		if (a->state == A_ERROR)
			break;

        /* handle reading the incoming stream */
        if(pth_event_occurred(a->eread))
        {
            log_debug(ZONE,"io read event for %d",a->sock);
            len = pth_read(a->sock, buff, 1024);
            if(len <= 0) break;

            if(xstream_eat(xs, buff, len) > XSTREAM_NODE) break;

			if (a->state == A_ERROR)
				break;
        }

        /* handle the packets to be sent to the socket */
        if(pth_event_occurred(a->emp))
        {
            log_debug(ZONE,"io incoming message event for %d",a->sock);

            /* flag that we're working */
            a->s->last = time(NULL);

            /* get packet */
            d = (drop)pth_msgport_get(a->s->mp);
            if(d == NULL) continue;
            p = d->p;

            /* write packet phase */
            block = xmlnode2str(p->x);
            if(pth_write(a->sock, block, strlen(block)) <= 0)
                break;

            /* all sent, yay */
            pool_free(p->p);
            p = NULL;
        }

        /* handle timeout if the handshake hasn't happened yet */
        if(a->emp == NULL && pth_event_occurred(a->etime))
        {
            log_debug(ZONE,"io timeout event for %d",a->sock);
            log_warn(NULL,"base_accept: Timeout on accepted socket");
            pth_write(a->sock,"<stream:error>Timed Out</stream:error>",38);
            pth_write(a->sock,"</stream:stream>",16);
            break;
        }
    }

    log_debug(ZONE,"read thread exiting for %d: %s",a->sock, strerror(errno));
    log_notice(NULL,"base_accept: connection died on accepted socket");

	/* If the acceptor's sink still points back to this acceptor, we can
	 * be confident that it is the primary handler for this instance and
	 * as such should be cleaned up appropriately */
	if (a->s!=NULL && (a->state == A_DUPLEX) && (a->s->a == a) )
	{
		/* Bounce current message */
		if(p != NULL)
		{
			log_warn(NULL,"base_accept Bouncing packet intended for %s",xmlnode_get_attrib(p->x,"to"));
			deliver_fail(p,"External Server Error");
		}

		/* Clean out and bounce message in the message queue */
		for(d = (drop)pth_msgport_get(a->s->mp);d != NULL; d = (drop)pth_msgport_get(a->s->mp))
		{
			log_warn(NULL,"base_accept Bouncing packet intended for %s",xmlnode_get_attrib(d->p->x,"to"));
			deliver_fail(d->p,"External Server Error");
		}
        a->s->a = NULL;
	}
	/* Cleanup a simplex socket */
	else if (a->s!=NULL &&a->state == A_SIMPLEX)
	{
		if(p != NULL)
        	base_accept_phandler(a->s->i, p, (void *)(a->s));
	}

	/* Release the events */
	pth_event_free(a->emp, PTH_FREE_THIS);
    pth_event_free(a->eread, PTH_FREE_THIS);
    /* Close the socket */
	close(a->sock);
    pool_free(a->p);

    return NULL;
}

/* A thread proc for listening on a new socket */
void *base_accept_listen(void *arg)
{
	listen_info li = (listen_info)arg;
    acceptor a;
    int root, sock;
    pool p;
    struct sockaddr_in sa;
    size_t sa_size = sizeof(sa);

    log_debug(ZONE,"new listener thread starting for %s",xmlnode2str(li->hosts));

    /* look at the port="" and optional ip="" attribs and start a listening socket */
    root = make_netsocket(li->port, li->ip, NETSOCKET_SERVER);
    if(root < 0 || listen(root, ACCEPT_LISTEN_BACKLOG) < 0)
    {
        log_debug(ZONE,"base_accept failed to listen on port %d for ip %s",li->port, li->ip);
        log_alert(NULL,"base_accept failed to listen on port %d for ip %s",li->port, li->ip);
        exit(1); /* don't start the server with a bad config */
        return NULL;
    }

    while(1)
    {
        /* when we get a new socket */
        sock = pth_accept(root, (struct sockaddr *) &sa, (int *) &sa_size);
        if(sock < 0)
        {
            log_warn(NULL,"base_accept error accepting: %s",strerror(errno));
            log_alert(NULL,"base_accept not listening on port %d for ip %s",li->port, li->ip);
            break;
        }

        /* Create a new acceptor for this socket */
		p = pool_new();
        a        = pmalloco(p, sizeof(_acceptor));
        a->p     = p;
        a->hosts = li->hosts;
        a->sock  = sock;

		/* XXX: Non-thread safe func used (inet_ntoa) */
        log_debug(ZONE,"new connection on port %d from ip %s as fd %d",li->port,inet_ntoa(sa.sin_addr),sock);
        log_notice(NULL,"base_accept: new connection on port %d from ip %s",li->port,inet_ntoa(sa.sin_addr));

        /* spawn io thread */
        pth_spawn(PTH_ATTR_DEFAULT, base_accept_io, (void *)a);
    }

    return NULL;
}

/* cleanup routine to make sure packets are getting delivered out of the DEFAULT sink */
result base_accept_plumber(void *arg)
{
	drop d;
    sink s = (sink)arg;
    if((time(NULL) - s->last) > ACCEPT_PACKET_TIMEOUT)
    { /* packets timed out without anywhere to send them */
        while((d=(drop)pth_msgport_get(s->mp))!=NULL)
        {
            log_warn(NULL,"base_accept Bouncing packet intended for %s",xmlnode_get_attrib(d->p->x,"to"));
            deliver_fail(d->p,"External Server Error");
        }
    }

    return r_DONE;
}

/* A global hash table keyed by ip:port string, with xmlnode
 * values that store an vattrib list of instance id->sinks */
HASHTABLE G_listeners;
pool      G_pool;

result base_accept_config(instance id, xmlnode x, void *arg)
{
    char *port, *ip, *secret;
	char *keybuf[22];
    xmlnode cur;
    sink s;

    port = xmlnode_get_data(xmlnode_get_tag(x, "port"));
    ip = xmlnode_get_data(xmlnode_get_tag(x, "ip"));
	secret = xmlnode_get_data(xmlnode_get_tag(x, "secret"));
    if(id == NULL)
    {
        spool sp = spool_new(xmlnode_pool(x));
        int error = 0;

        log_debug(ZONE,"base_accept_config validating configuration\n");
		if ((xmlnode_get_tag(x, "ip") == NULL) || 
		    (xmlnode_get_tag(x, "port") == NULL) || 
		    (xmlnode_get_tag(x,"secret") == NULL))
        {			
            spooler(sp,"<accept> requires the following subtags: <ip>, <port>, and <secret>",sp);
            error = 1;
        }		
        else if (port == NULL)
        {
            spooler(sp,"No port specified in <port> tag. Please specify a port.\n",sp);
            error = 1;
        }
        else if (secret == NULL)
        {
            spooler(sp,"No password specified in <secret> tag. Please provide a password.\n",sp);
            error = 1;
        }
        if (error) 
        {
            xmlnode_put_attrib(x,"error",spool_print(sp));
            return r_ERR;
        }
        return r_PASS;
    }

    log_debug(ZONE,"base_accept_config performing configuration %s\n",xmlnode2str(x));

	/* Format ip:port into a string */
	snprintf((char*)&keybuf, 22, "%s:%s", ip, port);

	/* Look for an existing xmlnode entry which uses the requested IP and port */
	cur = ghash_get(G_listeners, keybuf); 

    /* If no matching entry was found, create a new one for this
	 * instance and start a new listening thread */
	if(cur == NULL)
    {
		listen_info li;
		
		/* Create a new host tag */
		cur = xmlnode_new_tag("host");

		/* Insert ip:port->cur into hashtable */
		ghash_put(G_listeners, pstrdup(G_pool, (char*)&keybuf), cur);

		/* Create a listen struct to pass info to the listen thread */
		li = pmalloco(G_pool, sizeof(_listen_info));
		li->ip    = ip;
		li->port  = atoi(port);
		li->hosts = cur;
		
        /* Start a new listening thread and associate this <listen> tag with it */
		pth_spawn(PTH_ATTR_DEFAULT, base_accept_listen, (void *)li);
    }

	/* Setup the default sink for this instance */ 
    s       = pmalloco(id->p, sizeof(_sink));
	s->secret = secret;
    s->mp   = pth_msgport_create("base_accept");
    s->i    = id;
    s->last = time(NULL);
    s->p    = id->p; /* Use the instance's pool since, the sink is as permanent as the instance */

    log_debug(ZONE,"new sink %X",s);

	/* Register a packet handler and cleanup heartbeat for this instance */
    register_phandler(id, o_DELIVER, base_accept_phandler, (void *)s);
    register_beat(10, base_accept_plumber, (void *)s);

	/* Add the sink as a vattrib keyed by the instance id */
	xmlnode_put_vattrib(cur, s->i->id, (void*)s);

    return r_DONE;
}

void base_accept(void)
{
    log_debug(ZONE,"base_accept loading...\n");

	/* Setup global hash of ip:port->xmlnode */
	G_listeners = ghash_create(25, (KEYHASHFUNC)str_hash_code, (KEYCOMPAREFUNC)j_strcmp);

	/* Setup global memory pool for misc allocs */
	G_pool = pool_new();
	
    register_config("accept",base_accept_config,NULL);
}
