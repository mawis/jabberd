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
extern pool jabberd__runtime;

/* ---------------------------------------------------------
   base_connect - Connects to a specified host/port and 
                  exchanges xmlnodes with it over a socket
   ---------------------------------------------------------

   USAGE:
     <connect>
        <ip>1.2.3.4</ip>
	<port>2020</port>
	<secret>foobar</secret>
	<timeout>5</timeout>
     </connect>

   TODO: 
   - Add packet aging/delivery heartbeat
*/

/* Connection states */
typedef enum { conn_CLOSED, conn_OPEN, conn_AUTHD } conn_state;

/* conn_info - stores thread data for a connection */
typedef struct
{
    mio           io;
    conn_state    state;	/* Connection status (closed, opened, auth'd) */
    char*         hostip;	/* Server IP */
    u_short       hostport;	/* Server port */
    char*         secret;	/* Connection secret */
    int           timeout;      /* timeout for connect() in seconds */
    pool          mempool;	/* Memory pool for this struct */
    char*         keybuf;
    instance      inst;         /* Matching instance for this connection */
    pth_msgport_t   write_queue;	/* Queue of write_buf packets which need to be written */
} *conn_info, _conn_info;

/* conn_write_buf - stores a dpacket that needs to be written to the socket */
typedef struct
{
    pth_message_t head;
    dpacket     packet;
} *conn_write_buf, _conn_write_buf;


/* Deliver packets to the socket io thread */
result base_connect_deliver(instance i, dpacket p, void* arg)
{
    conn_info ci      = (conn_info)arg;

    /* Insert the message into the write_queue if we don't 
       have an MIO socket yet.. */
    if (ci->io == NULL)
    {
	    conn_write_buf entry = pmalloco(p->p, sizeof(_conn_write_buf));
	    entry->packet = p;
	    pth_msgport_put(ci->write_queue, (pth_message_t*)entry);
    }
    /* Otherwise, write directly to the MIO socket */
    else
    {
	    mio_write(ci->io, p->x, NULL, 0);
    }

    return r_DONE;

}

void base_connect_process_xml(mio m, int state, void* arg, xmlnode x)
{
    conn_info ci = (conn_info)arg;

    switch (state)
    {
        case MIO_NEW:
        {
	        xmlnode headernode;
	        char*   header;

	        ci->state = conn_OPEN;
	        ci->io = m;

	        /* Send a stream header to the server */
            log_debug(ZONE, "base_connecting: %X, %X, %X, %s", ci, ci->inst, ci->inst->id, ci->inst->id); 
	        headernode = xstream_header("jabber:component:accept", ci->inst->id, NULL);
	        header = xstream_header_char(headernode);
	        mio_write(m, headernode, header, strlen(header));

	        break;
        }
        case MIO_XML_ROOT:
        {
	        char* strbuf = NULL;
	        char  hashbuf[41];
	        xmlnode cur;

	        /* Make sure that the incoming stream matches our outgoing.. */
	        if (j_strcmp(xmlnode_get_attrib(x, "from"), ci->inst->id) != 0)
	            log_warn(ci->inst->id, "From/to on stream header do not match: %s/%s",
		     xmlnode_get_attrib(x, "from"), ci->inst->id);

	        /* Extract stream ID and generate a key to hash */
	        strbuf = spools(x->p, xmlnode_get_attrib(x, "id"), ci->secret, x->p);
	        /* Calculate SHA hash */
	        shahash_r(strbuf, hashbuf);

	        /* Build a handshake packet */
	        cur = xmlnode_new_tag("handshake");
	        xmlnode_insert_cdata(cur, hashbuf, -1);
	        /* Transmit handshake */
	        mio_write(m, cur, NULL, 0);

	        break;
        }
        case MIO_XML_NODE:
        {
	        /* Only deliver packets after the connection is auth'd */
	        if (ci->state == conn_AUTHD)
	        {
	            deliver(dpacket_new(x), ci->inst);
	        }
	        else
	        {
	            /* If a handshake packet is recv'd from the server, we
	            have successfully auth'd -- go ahead and update the
	            connection state */
	            if (strcmp(xmlnode_get_name(x), "handshake") == 0)
	            {
		            /* Flush all packets queued up for delivery */
		            conn_write_buf b = (conn_write_buf) pth_msgport_get(ci->write_queue);
		            while (b != NULL)
		            {
		                mio_write(ci->io, b->packet->x, NULL, 0);
		            }
		            /* Update connection state flag */
		            ci->state = conn_AUTHD;
	            }
    
	            /* Drop the packet, regardless */
	            xmlnode_free(x);
	        }
	        break;
        }
        case MIO_ERROR:
        case MIO_CLOSED:
	        /* Always restart the connection after it closes for any reason */
	        ci->state = conn_CLOSED;
            /* pause 2 seconds, and reconnect */
            log_debug(ZONE, "Base Connect Failed to connect to %s:%d Retry in 2 seconds...", ci->hostip, ci->hostport);
            pth_sleep(2);
	        mio_connect(ci->hostip, ci->hostport, base_connect_process_xml, (void*)ci, ci->timeout, NULL, mio_handlers_new(NULL, NULL, MIO_XML_PARSER));
    }
}

HASHTABLE G_conns;
pool      G_pool;

void base_connect_conn_cleanup(void *arg)
{
    conn_info ci = (conn_info)arg;
    log_debug(ZONE, "CLEANUP CONN");
    ghash_remove(G_conns, ci->keybuf);
}

void base_connect_cleanup(void *arg)
{
    log_debug(ZONE, "CLEANUP");
    ghash_destroy(G_conns);
}

result base_connect_config(instance id, xmlnode x, void *arg)
{
     char*     ip     = NULL;
     char*     port   = NULL;
     char*     secret = NULL;
     char      keybuf[24];
     int       timeout;
     conn_info ci = NULL;

     /* Extract info */
     ip     = xmlnode_get_data(xmlnode_get_tag(x, "ip"));
     port   = xmlnode_get_data(xmlnode_get_tag(x, "port"));
     secret = xmlnode_get_data(xmlnode_get_tag(x, "secret"));

     timeout = j_atoi(xmlnode_get_data(xmlnode_get_tag(x, "timeout")), 5);

     if(id == NULL)
     {
        log_debug(ZONE,"base_accept_config validating configuration\n");
        if((ip     == NULL) ||
           (port   == NULL) ||
           (secret == NULL) )
        {
            xmlnode_put_attrib(x, "error", "<connect> requires the following subtags: <ip>, <port>, and <secret>");
            return r_ERR;
        }
        return r_PASS;
     }

     if(G_conns == NULL)
     {
             log_debug(ZONE, "createing hash for base_connect");
        G_conns = ghash_create(23, (KEYHASHFUNC)str_hash_code, (KEYCOMPAREFUNC)j_strcmp);
        G_pool = jabberd__runtime;
        pool_cleanup(G_pool, base_connect_cleanup, NULL);
     }
     
     /* Format ip:port into a key */
     snprintf((char*)&keybuf, 22, "%s:%s", ip, port);

     /* Search for an existing connection structure */
    ci = ghash_get(G_conns, keybuf);
    log_debug(ZONE, "id: %s, found item %X for %s in hash", id->id, ci,(char*)&keybuf);

     /* No connection was found, so create one.. */
     if (ci == NULL)
     {
	  /* Allocate a conn structures, using this instances' mempool */
	  ci              = pmalloco(id->p, sizeof(_conn_info));
	  ci->mempool     = id->p;
	  ci->state       = conn_CLOSED;
      ci->inst        = id;
	  ci->hostip      = pstrdup(ci->mempool, ip);
	  ci->hostport    = atoi(port);
	  ci->secret      = pstrdup(ci->mempool, secret);
	  ci->write_queue = pth_msgport_create(ci->hostip);
      ci->timeout     = timeout;
      ci->keybuf      = pstrdup(id->p, (char*)&keybuf);

      ghash_put(G_conns, pstrdup(G_pool, (char*)&keybuf), ci);
      pool_cleanup(id->p, base_connect_conn_cleanup, (void*)ci);

     }

     /* Register a handler to recieve inbound data for this instance */
     register_phandler(id, o_DELIVER, base_connect_deliver, (void*)ci);
     
     /* Make a connection to the host */
     mio_connect(ip, atoi(port), base_connect_process_xml, (void*)ci, timeout, NULL, mio_handlers_new(NULL, NULL, MIO_XML_PARSER));

     log_debug(ZONE, "Activating configuration: %s\n", xmlnode2str(x));
     return r_DONE;
}

void base_connect(void)
{
    log_debug(ZONE,"base_connect loading...\n");
    register_config("connect",base_connect_config,NULL);
}
