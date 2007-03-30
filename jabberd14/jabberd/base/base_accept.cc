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

/**
 * @file base_accept.cc
 * @brief opens a socket to handle incoming connections using the component protocol defined in XEP-0114
 */
 
#include "jabberd.h"

#define A_ERROR  -1
#define A_READY   1

typedef struct queue_struct {
    int stamp;
    xmlnode x;
    struct queue_struct *next;
} *queue, _queue;

typedef struct accept_instance_st {
    mio m;
    int state;
    char *id;
    pool p;
    instance i;
    char *ip;
    char *secret;
    int port;
    int timeout;
    int restrict_var;
    xdbcache offline;
    jid offjid;
    queue q;
    /* dpacket dplast; */
} *accept_instance, _accept_instance;

static void base_accept_queue(accept_instance ai, xmlnode x) {
    queue q;
    if(ai == NULL || x == NULL) return;

    q = static_cast<queue>(pmalloco(xmlnode_pool(x),sizeof(_queue)));
    q->stamp = time(NULL);
    q->x = x;
    q->next = ai->q;
    ai->q = q;
}

/* Write packets to a xmlio object */
static result base_accept_deliver(instance i, dpacket p, void* arg) {
    accept_instance ai = (accept_instance)arg;

    /* Insert the message into the write_queue if we don't have a MIO socket yet.. */
    if (ai->state == A_READY) {
        /*
         * TSBandit -- this doesn't work, since many components simply modify the node in-place
        if(ai->dplast == p) // don't return packets that they sent us! circular reference!
        {
            deliver_fail(p,"Circular Refernce Detected");
        }
        else
        */
            mio_write(ai->m, p->x, NULL, 0);
        return r_DONE;
    }

    base_accept_queue(ai, p->x);
    return r_DONE;
}


/* Handle incoming packets from the xstream associated with an MIO object */
static void base_accept_process_xml(mio m, int state, void* arg, xmlnode x, char* unused1, int unused2) {
    accept_instance ai = (accept_instance)arg;
    xmlnode cur, off;
    queue q, q2;
    char hashbuf[41];
    jpacket jp;

    log_debug2(ZONE, LOGT_XML, "process XML: m:%X state:%d, arg:%X, x:%X", m, state, arg, x);

    switch (state) {
        case MIO_XML_ROOT:
           /* Send header w/ proper namespace, using instance i */
            cur = xstream_header(NULL, ai->i->id);
            /* Save stream ID for auth'ing later */
            ai->id = pstrdup(ai->p, xmlnode_get_attrib_ns(cur, "id", NULL));
	    mio_write_root(m, cur, 2);
            break;

        case MIO_XML_NODE:
            /* If aio has been authenticated previously, go ahead and deliver the packet */
            if(ai->state == A_READY  && m == ai->m) {
                /*
                 * TSBandit -- this doesn't work.. since many components modify the node in-place
                ai->dplast = dpacket_new(x);
                deliver(ai->dplast, ai->i);
                ai->dplast = NULL;
                */

                /* if we are supposed to be careful about what comes from this socket */
                if(ai->restrict_var)
                {
                    jp = jpacket_new(x);
                    if(jp->type == JPACKET_UNKNOWN || jp->to == NULL || jp->from == NULL || deliver_hostcheck(jp->from->server) != ai->i)
                    {
                        jutil_error_xmpp(x,XTERROR_INTERNAL);
                        mio_write(m,x,NULL,0);
                        return;
                    }
                }

                deliver(dpacket_new(x), ai->i);
                return;
            }

            /* only other packets are handshakes */
            if (j_strcmp(xmlnode_get_localname(x), "handshake") != 0 || j_strcmp(xmlnode_get_namespace(x), NS_SERVER) != 0) {
                mio_write(m, NULL, "<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Must send handshake first.</text></stream:error>", -1);
                mio_close(m);
                break;
            }

            /* Create and check a SHA hash of this instance's password & SID */
            shahash_r(spools(xmlnode_pool(x), ai->id, ai->secret, xmlnode_pool(x)), hashbuf);
            if (j_strcmp(hashbuf, xmlnode_get_data(x)) != 0) {
                mio_write(m, NULL, "<stream:error><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Invalid handshake</text></stream:error>", -1);
                mio_close(m);
		break;
            }

            /* Send a handshake confirmation */
            mio_write(m, NULL, "<handshake/>", -1);

            /* check for existing conenction and kill it */
            if (ai->m != NULL) {
                log_warn(ai->i->id, "Socket override by another connection from %s",mio_ip(m));
		mio_write(ai->m, NULL, "<stream:error><conflict xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Socket override by another connection.</text></stream:error>", -1);
                mio_close(ai->m);
            }

            /* hook us up! */
            ai->m = m;
            ai->state = A_READY;

            /* if offline, get anything stored and deliver */
            if (ai->offline != NULL) {
                off = xdb_get(ai->offline, ai->offjid, "base:accept:offline");
                for (cur = xmlnode_get_firstchild(off); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
                    /* dup and deliver stored packets... XXX should probably handle NS_EXPIRE, I get lazy at 6am */
                    mio_write(m,xmlnode_dup(cur),NULL,0);
                    xmlnode_hide(cur);
                }
                xdb_set(ai->offline, ai->offjid, "base:accept:offline", off);
                xmlnode_free(off);
            }

            /* flush old queue */
            q = ai->q;
            while (q != NULL) {
                q2 = q->next;
                mio_write(m, q->x, NULL, 0);
                q = q2;
            }
            ai->q = NULL;

            break;

        case MIO_ERROR:
            /* make sure it's the important one */
            if (m != ai->m)
                return;

            ai->state = A_ERROR;

            /* clean up any tirds */
            while ((cur = mio_cleanup(m)) != NULL)
                deliver_fail(dpacket_new(cur), N_("External Server Error"));

            return;

        case MIO_CLOSED:
            /* make sure it's the important one */
            if (m != ai->m)
                return;

            log_debug2(ZONE, LOGT_IO, "closing accepted socket");
            ai->m = NULL;
            ai->state = A_ERROR;

            return;
        default:
            return;
    }
    xmlnode_free(x);
}

/* bounce messages/pres-s10n differently if in offline mode */
static void base_accept_offline(accept_instance ai, xmlnode x) {
    jpacket p;
    char errmsg[256] = "";

    if(ai->offline == NULL) {
	snprintf(errmsg, sizeof(errmsg), messages_get(xmlnode_get_lang(x), N_("Component '%s' is not connected to server")),
		ai->i==NULL ? "(NULL)" :
		ai->i->id!= NULL ? ai->i->id : "(null)");
        deliver_fail(dpacket_new(x), errmsg);
        return;
    }

    p = jpacket_new(x);
    switch(p->type) {
        case JPACKET_MESSAGE:
            /* XXX should probably handle offline events I guess, more lazy */
        case JPACKET_S10N:
            if(xdb_act_path(ai->offline, ai->offjid, "base:accept:offline", "insert", NULL, NULL, x) == 0) {
                xmlnode_free(x);
                return;
            }
            break;
        default:
            break;
    }

    snprintf(errmsg, sizeof(errmsg), messages_get(xmlnode_get_lang(x), N_("delivery to '%s': Internal Timeout")),
	    ai->i==NULL ? "(NULL)" : ai->i->id!= NULL ? ai->i->id : "(null)");
    deliver_fail(dpacket_new(x), errmsg);
}

/* check the packet queue for stale packets */
static result base_accept_beat(void *arg) {
    accept_instance ai = (accept_instance)arg;
    queue bouncer, lastgood, cur, next;
    int now = time(NULL);

    cur = ai->q;
    bouncer = lastgood = NULL;
    while(cur != NULL) {
        if( (now - cur->stamp) <= ai->timeout) {
            lastgood = cur;
            cur = cur->next;
            continue;
        }

        /* timed out sukkah! */
        next = cur->next;
        if(lastgood == NULL)
            ai->q = next;
        else
            lastgood->next = next;

        /* place in a special queue to bounce later on */
        cur->next = bouncer;
        bouncer = cur;

        cur = next;
    }

    while(bouncer != NULL) {
        next = bouncer->next;
        base_accept_offline(ai, bouncer->x);
        bouncer = next;
    }
    
    return r_DONE;
}

static result base_accept_config(instance id, xmlnode x, void *arg) {
    char *secret = NULL;
    accept_instance inst;
    int port = 0;
    xht namespaces = NULL;
    char *ip = NULL;
    int restrict_var = 0;
    int offline = 0;
    int timeout = 0;

    namespaces = xhash_new(3);
    xhash_put(namespaces, "", const_cast<char*>(NS_JABBERD_CONFIGFILE));
    pool temp_pool = pool_new();
    secret = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "secret", namespaces, temp_pool), 0));
    ip = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "ip", namespaces, temp_pool), 0));
    port = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "port", namespaces, temp_pool), 0)), 0);
    restrict_var = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "restrict", namespaces, temp_pool), 0)) != NULL ? 1 : 0;
    offline = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "offline", namespaces, temp_pool), 0)) != NULL ? 1 : 0;
    timeout = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "timeout", namespaces, temp_pool), 0)), 10);
    xhash_free(namespaces);

    /* free temp_pool again */
    pool_free(temp_pool);
    temp_pool = NULL;

    if(id == NULL) {
        log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_accept_config validating configuration...");
        if (port == 0 || secret == NULL) {
            xmlnode_put_attrib_ns(x, "error", NULL, NULL, "<accept> requires the following subtags: <port>, and <secret>");
            return r_ERR;
        }		
        return r_PASS;
    }

    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_accept_config performing configuration %s\n", xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));

    /* Setup the default sink for this instance */ 
    inst              = static_cast<accept_instance>(pmalloco(id->p, sizeof(_accept_instance)));
    inst->p           = id->p;
    inst->i           = id;
    inst->secret      = secret;
    inst->ip          = ip;
    inst->port        = port;
    inst->timeout     = timeout;
    if (restrict_var)
        inst->restrict_var = 1;
    if (offline) {
        inst->offline = xdb_cache(id);
        inst->offjid = jid_new(id->p,id->id);
    }

    /* Start a new listening thread and associate this <listen> tag with it */
    if (mio_listen(inst->port, inst->ip, base_accept_process_xml, inst, mio_handlers_new(NULL, NULL, MIO_XML_PARSER)) == NULL) {
        xmlnode_put_attrib_ns(x, "error", NULL, NULL, "<accept> unable to listen on the configured ip and port");
        return r_ERR;
    }

    /* Register a packet handler and cleanup heartbeat for this instance */
    register_phandler(id, o_DELIVER, base_accept_deliver, (void *)inst);

    /* timeout check */
    register_beat(inst->timeout, base_accept_beat, (void *)inst);

    return r_DONE;
}

/**
 * register the accept base handler
 *
 * @param p memory pool used to register the configuration handler of this handler (must be available for the livetime of jabberd)
 */
void base_accept(pool p) {
    log_debug2(ZONE, LOGT_INIT, "base_accept loading...\n");
    register_config(p, "accept",base_accept_config,NULL);
}
