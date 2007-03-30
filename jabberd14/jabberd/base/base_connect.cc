/*
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2007 Matthias Wimmer
 *
 * This file is part of jabberd14.
 *
 * This software is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

#include "jabberd.h"

/**
 * @file base_connect.cc
 * @brief connects to another instance using the component protocol
 *
 * This base handler implements connecting to another jabberd or other server instance
 * using the component protocol defined in XEP-0114.
 */

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
        <tries>15</tries>
     </connect>

   TODO: 
   - Add packet aging/delivery heartbeat
*/

/* Connection states */
typedef enum { conn_DIE, conn_CLOSED, conn_OPEN, conn_AUTHD } conn_state;

/* conn_info - stores thread data for a connection */
typedef struct {
    mio           io;
    conn_state    state;	/* Connection status (closed, opened, auth'd) */
    char*         hostip;	/* Server IP */
    u_short       hostport;	/* Server port */
    char*         secret;	/* Connection secret */
    int           timeout;      /* timeout for connect() in seconds */
    int           tries_left;   /* how many more times are we going to try to connect? */
    pool          mempool;	/* Memory pool for this struct */
    instance      inst;         /* Matching instance for this connection */
    pth_msgport_t   write_queue;	/* Queue of write_buf packets which need to be written */
    dpacket dplast; /* special circular reference detector */
} *conn_info, _conn_info;

/* conn_write_buf - stores a dpacket that needs to be written to the socket */
typedef struct {
    pth_message_t head;
    dpacket     packet;
} *conn_write_buf, _conn_write_buf;

static void base_connect_process_xml(mio m, int state, void* arg, xmlnode x, char* unused1, int unused2);

/* Deliver packets to the socket io thread */
static result base_connect_deliver(instance i, dpacket p, void* arg) {
    conn_info ci = (conn_info)arg;

    /* Insert the message into the write_queue if we don't have an MIO socket yet.. */
    if (ci->state != conn_AUTHD) {
        conn_write_buf entry = static_cast<conn_write_buf>(pmalloco(p->p, sizeof(_conn_write_buf)));
        entry->packet = p;
        pth_msgport_put(ci->write_queue, (pth_message_t*)entry);
    } else {
	/* Otherwise, write directly to the MIO socket */
        if (ci->dplast == p) /* don't handle packets that we generated! doh! */
            deliver_fail(p, N_("Circular Reference Detected"));
        else
            mio_write(ci->io, p->x, NULL, 0);
    }

    return r_DONE;
}

/* this runs from another thread under mtq */
static void base_connect_connect(void *arg) {
    conn_info ci = (conn_info)arg;
    pth_sleep(2); /* take a break */
    mio_connect(ci->hostip, ci->hostport, base_connect_process_xml, ci, ci->timeout, mio_handlers_new(NULL, NULL, MIO_XML_PARSER));
}

static void base_connect_process_xml(mio m, int state, void* arg, xmlnode x, char* unused1, int unused2) {
    conn_info ci = (conn_info)arg;
    xmlnode cur;
    char  hashbuf[41];

    log_debug2(ZONE, LOGT_XML, "process XML: m:%X state:%d, arg:%X, x:%X", m, state, arg, x);

    switch (state) {
        case MIO_NEW:

            ci->state = conn_OPEN;
            ci->io = m;

            /* Send a stream header to the server */
            log_debug2(ZONE, LOGT_IO, "base_connecting: %X, %X, %s", ci, ci->inst, ci->inst->id); 

            cur = xstream_header(ci->inst->id, NULL);
	    mio_write_root(m, cur, 2);

            return;

        case MIO_XML_ROOT:
            /* Extract stream ID and generate a key to hash */
            shahash_r(spools(x->p, xmlnode_get_attrib_ns(x, "id", NULL), ci->secret, x->p), hashbuf);

            /* Build a handshake packet */
            cur = xmlnode_new_tag_ns("handshake", NULL, NS_SERVER);
            xmlnode_insert_cdata(cur, hashbuf, -1);

            /* Transmit handshake */
	    mio_write(m, cur, NULL, 0);
            xmlnode_free(x);
            return;

        case MIO_XML_NODE:
            /* Only deliver packets after the connection is auth'd */
            if (ci->state == conn_AUTHD) {
                ci->dplast = dpacket_new(x); /* store the addr of the dpacket we're sending to detect circular delevieries */
                deliver(ci->dplast, ci->inst);
                ci->dplast = NULL;
                return;
            }

            /* If a handshake packet is recv'd from the server, we have successfully auth'd -- go ahead and update the connection state */
            if (j_strcmp(xmlnode_get_localname(x), "handshake") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_SERVER) == 0) {
                /* Flush all packets queued up for delivery */
                conn_write_buf b;
                while ((b = (conn_write_buf) pth_msgport_get(ci->write_queue)) != NULL)
                    mio_write(ci->io, b->packet->x, NULL, 0);
                /* Update connection state flag */
                ci->state = conn_AUTHD;
            }
            xmlnode_free(x);
            return;

        case MIO_CLOSED:

            if(ci->state == conn_DIE)
                return; /* server is dying */

            /* Always restart the connection after it closes for any reason */
            ci->state = conn_CLOSED;
            if(ci->tries_left != -1) 
                ci->tries_left--;

            if(ci->tries_left == 0) {
                fprintf(stderr, "Base Connect Failed: service %s was unable to connect to %s:%d, unrecoverable error, exiting", ci->inst->id, ci->hostip, ci->hostport);
                exit(1);
            }

            /* pause 2 seconds, and reconnect */
            log_debug2(ZONE, LOGT_IO, "Base Connect Failed to connect to %s:%d Retry [%d] in 2 seconds...", ci->hostip, ci->hostport, ci->tries_left);
            mtq_send(NULL,ci->mempool,base_connect_connect,(void *)ci);

            return;
    }
}

static void base_connect_kill(void *arg) {
    conn_info ci = (conn_info)arg;
    ci->state = conn_DIE;
}

static result base_connect_config(instance id, xmlnode x, void *arg) {
    char*	secret = NULL;
    int		timeout = 5;
    int		tries = -1;
    char*	ip = NULL;
    int		port = 0;
    conn_info	ci = NULL;
    xht		namespaces = NULL;

    /* Extract info */
    namespaces = xhash_new(3);
    xhash_put(namespaces, "", const_cast<char*>(NS_JABBERD_CONFIGFILE));
    pool temp_pool = pool_new();
    ip = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "ip", namespaces, temp_pool), 0));
    port = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "port", namespaces, temp_pool), 0)), 0);
    secret = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "secret", namespaces, temp_pool), 0));
    timeout = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "timeout", namespaces, temp_pool), 0)), 5);
    tries = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "tries", namespaces, temp_pool), 0)), -1);
    xhash_free(namespaces);

    /* free the temp_pool again */
    pool_free(temp_pool);
    temp_pool = NULL;

    if(id == NULL) {
        log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_accept_config validating configuration\n");
        if(port == 0 || (secret == NULL)) {
            xmlnode_put_attrib_ns(x, "error", NULL, NULL, "<connect> requires the following subtags: <port>, and <secret>");
            return r_ERR;
        }
        return r_PASS;
    }

    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "Activating configuration: %s\n", xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));

    /* Allocate a conn structures, using this instances' mempool */
    ci              = static_cast<conn_info>(pmalloco(id->p, sizeof(_conn_info)));
    ci->mempool     = id->p;
    ci->state       = conn_CLOSED;
    ci->inst        = id;
    ci->hostip      = pstrdup(ci->mempool, ip);
    if (ci->hostip == NULL)
	ci->hostip = pstrdup(ci->mempool, "127.0.0.1");
    ci->hostport    = port;
    ci->secret      = pstrdup(ci->mempool, secret);
    ci->write_queue = pth_msgport_create(ci->hostip);
    ci->timeout     = timeout;
    ci->tries_left  = tries;

    /* Register a handler to recieve inbound data for this instance */
    register_phandler(id, o_DELIVER, base_connect_deliver, (void*)ci);
     
    /* Make a connection to the host, in another thread */
    mtq_send(NULL,ci->mempool,base_connect_connect,(void *)ci);

    register_shutdown(base_connect_kill, (void *)ci);

    return r_DONE;
}

/**
 * register the connect base handler
 *
 * @param p memory pool used to register the handler for the &lt;connect/&gt; configuration element (must be available for the livetime of jabberd)
 */
void base_connect(pool p) {
    log_debug2(ZONE, LOGT_INIT, "base_connect loading...\n");
    register_config(p, "connect",base_connect_config,NULL);
}
