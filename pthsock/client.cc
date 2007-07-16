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
 * @dir pthsock
 * @brief implementation of the client connection manager
 *
 * This directory contains the implementation of the pthsock_client component
 * for the jabberd14 server. The task of this component is to accept incoming
 * TCP/IP requests from Jabber clients, and to forward the received stanzas
 * to the session manager of the user. It is the task of the client connection
 * manager to multiplex the stanzas of all incoming connection by sending them
 * through the XML router to the session manager, that handles the domain of the
 * user. Therefore the session manager do not themself have to manage all the
 * user connections.
 */

/**
 * @file client.cc
 * @brief this file implements the client connection manager
 */

/*
    <service id="pthsock client">
      <host>pth-csock.127.0.0.1</host> <!-- Can be anything -->
      <load>
	    <pthsock_client>../load/pthsock_client.so</pthsock_client>
      </load>
      <pthcsock xmlns='jabber:config:pth-csock'>
        <alias to="main.host.com">alias.host.com</alias>
        <alias to="default.host.com"/>
        <listen>5222</listen>            <!-- Port to listen on -->
        <!-- allow 25 connects per 5 seconts -->
        <rate time="5" points="25"/> 
      </pthcsock>
    </service>
*/

#include <jabberd.h>
#define DEFAULT_AUTH_TIMEOUT 120
#define DEFAULT_HEARTBEAT 60

/* socket manager instance */
typedef struct smi_st {
    instance i;
    int auth_timeout;
    int heartbeat;
    xht aliases;
    xht users;
    xht std_namespace_prefixes;	/**< standard prefixes for using with xmlnode_get_tags() */
    xmlnode cfg;
    char *host;
    int register_feature;	/**< should we advertise the register stream feature? */
} *smi, _smi;

typedef enum { state_UNKNOWN, state_AUTHD } user_state;
typedef struct edata_st {
    smi si;
    int aliased;
    jid session_id;
    jid sending_id;
    user_state state;
    char *client_id, *sid, *res, *auth_id;
    time_t connect_time;
    time_t last_activity;
    mio m;
    pth_msgport_t pre_auth_mp;
} _cdata,*cdata;


/* makes a route packet, intelligently */
static xmlnode pthsock_make_route(xmlnode x, const char *to, const char *from, const char *type) {
    xmlnode newx;
    newx = x ? xmlnode_wrap_ns(x, "route", NULL, NS_SERVER) : xmlnode_new_tag_ns("route", NULL, NS_SERVER);

    if (type != NULL) 
        xmlnode_put_attrib_ns(newx, "type", NULL, NULL, type);

    if (to != NULL) 
        xmlnode_put_attrib_ns(newx, "to", NULL, NULL, to);

    if (from != NULL) 
        xmlnode_put_attrib_ns(newx, "from", NULL, NULL, from);

    return newx;
}

/* incoming jabberd deliver()ed packets */
static result pthsock_client_packets(instance id, dpacket p, void *arg) {
    smi s__i = (smi)arg;
    cdata cdcur;
    mio m;
    int fd = 0;

    if (p->id->user != NULL)
        fd = atoi(p->id->user); 
    
    if (p->type != p_ROUTE || fd == 0) {
	/* we only want <route/> packets or ones with a valid connection */
        log_warn(p->host, "pthsock_client bouncing invalid %s packet from %s", xmlnode_get_localname(p->x), xmlnode_get_attrib_ns(p->x, "from", NULL));
        deliver_fail(p, N_("invalid client packet"));
        return r_DONE;
    }


    if ((cdcur = static_cast<cdata>(xhash_get(s__i->users, xmlnode_get_attrib_ns(p->x, "to", NULL)))) == NULL) {
        if (!j_strcmp(xmlnode_get_attrib_ns(p->x, "type", NULL), "session")) {
            jutil_tofrom(p->x);
            xmlnode_put_attrib_ns(p->x, "type", NULL, NULL, "error");
            deliver(dpacket_new(p->x), s__i->i);
        } else {
            xmlnode_free(p->x);
        }
        return r_DONE;
    }



    if (fd != cdcur->m->fd || cdcur->m->state != state_ACTIVE)
        m = NULL;
    else if (j_strcmp(p->id->resource,cdcur->res) != 0)
        m = NULL;
    else
        m = cdcur->m;

    if (m == NULL) { 
        if (j_strcmp(xmlnode_get_attrib_ns(p->x, "type", NULL), "error") == 0) {
	    /* we got a 510, but no session to end */
            log_debug2(ZONE, LOGT_SESSION, "[%s] received Session close for non-existant session: %s", ZONE, xmlnode_get_attrib_ns(p->x, "from", NULL));
            xmlnode_free(p->x);
            return r_DONE;
        }

        log_debug2(ZONE, LOGT_SESSION, "[%s] connection not found for %s, closing session", ZONE, xmlnode_get_attrib_ns(p->x, "from", NULL));

        jutil_tofrom(p->x);
        xmlnode_put_attrib_ns(p->x, "type", NULL, NULL, "error");

        deliver(dpacket_new(p->x), s__i->i);
        return r_DONE;
    }

    log_debug2(ZONE, LOGT_DELIVER, "[%s] %s has an active session, delivering packet", ZONE, xmlnode_get_attrib_ns(p->x, "from", NULL));
    if (j_strcmp(xmlnode_get_attrib_ns(p->x, "type", NULL), "error") == 0) {
	/* <route type="error" means we were disconnected */
        log_debug2(ZONE, LOGT_SESSION, "[%s] closing down session %s at request of session manager", ZONE, xmlnode_get_attrib_ns(p->x, "from", NULL));
        mio_write(m, NULL, "<stream:error><conflict xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Disconnected</text></stream:error></stream:stream>", -1);
        mio_close(m);
        xmlnode_free(p->x);
        return r_DONE;
    }
    else if(cdcur->state == state_UNKNOWN && j_strcmp(xmlnode_get_attrib_ns(p->x, "type", NULL), "auth") == 0) {
	/* look for our auth packet back */
        char *type = xmlnode_get_attrib_ns(xmlnode_get_firstchild(p->x), "type", NULL);
        char *id   = xmlnode_get_attrib_ns(xmlnode_get_list_item(xmlnode_get_tags(p->x, "iq", s__i->std_namespace_prefixes), 0), "id", NULL);
        if ((j_strcmp(type, "result") == 0) && j_strcmp(cdcur->auth_id, id) == 0) {
	    /* update the cdata status if it's a successfull auth */
            xmlnode x;
            log_debug2(ZONE, LOGT_AUTH|LOGT_SESSION, "[%s], auth for user successful", ZONE);
            /* notify SM to start a session */
            x = pthsock_make_route(NULL, jid_full(cdcur->session_id), cdcur->client_id, "session");
            log_debug2(ZONE, LOGT_SESSION, "[%s] requesting Session Start for %s", ZONE, xmlnode_get_attrib_ns(p->x, "from", NULL));
            deliver(dpacket_new(x), s__i->i);
        } else if (j_strcmp(type,"error") == 0) {
            log_record(jid_full(jid_user(cdcur->session_id)), "login", "fail", "%s %s %s", mio_ip(cdcur->m), xmlnode_get_attrib_ns(xmlnode_get_list_item(xmlnode_get_tags(p->x, "iq/error", s__i->std_namespace_prefixes), 0), "code", NULL), cdcur->session_id->resource);
        }
    } else if (cdcur->state == state_UNKNOWN && j_strcmp(xmlnode_get_attrib_ns(p->x, "type", NULL), "session") == 0) {
	/* got a session reply from the server */
        mio_wbq q;

        cdcur->state = state_AUTHD;
        log_record(jid_full(jid_user(cdcur->session_id)), "login", "ok", "%s %s", mio_ip(cdcur->m), cdcur->session_id->resource);
        /* change the host id */
        cdcur->session_id = jid_new(m->p, xmlnode_get_attrib_ns(p->x, "from", NULL));
        xmlnode_free(p->x);
        /* if we have packets in the queue, write them */
        while ((q = (mio_wbq)pth_msgport_get(cdcur->pre_auth_mp)) != NULL) {
            q->x = pthsock_make_route(q->x, jid_full(cdcur->session_id), cdcur->client_id, NULL);
            deliver(dpacket_new(q->x), s__i->i);
        }
        pth_msgport_destroy(cdcur->pre_auth_mp);
        cdcur->pre_auth_mp = NULL;
        return r_DONE;
    }


    if (xmlnode_get_firstchild(p->x) == NULL || xhash_get(s__i->users, xmlnode_get_attrib_ns(p->x, "to", NULL)) == NULL) {
        xmlnode_free(p->x);
    } else {
        log_debug2(ZONE, LOGT_IO, "[%s] Writing packet to MIO: %s", ZONE, xmlnode_serialize_string(xmlnode_get_firstchild(p->x), xmppd::ns_decl_list(), 0));
        mio_write(m, xmlnode_get_firstchild(p->x), NULL, 0);
        cdcur->last_activity = time(NULL);
    }

    return r_DONE;
}

static cdata pthsock_client_cdata(mio m, smi s__i) {
    cdata cd;
    char buf[100];

    cd               = static_cast<cdata>(pmalloco(m->p, sizeof(_cdata)));
    cd->pre_auth_mp  = pth_msgport_create("pre_auth_mp");
    cd->state        = state_UNKNOWN;
    cd->connect_time = time(NULL);
    cd->last_activity = cd->connect_time;
    cd->m            = m;
    cd->si           = s__i;

    /* HACK to fix race conditon */
    snprintf(buf, sizeof(buf), "%X", m);
    cd->res = pstrdup(m->p, buf);

    /* we use <fd>@host to identify connetions */
    snprintf(buf, sizeof(buf), "%d@%s/%s", m->fd, s__i->host, cd->res);
    cd->client_id = pstrdup(m->p, buf);

    return cd;
}

static void pthsock_client_read(mio m, int flag, void *arg, xmlnode x, char* unused1, int unused2) {
    cdata cd = (cdata)arg;
    xmlnode h;
    char *alias, *to;
    int version = 0;

    if(cd == NULL) 
        return;

    log_debug2(ZONE, LOGT_IO, "[%s] pthsock_client_read called with: m:%X flag:%d arg:%X", ZONE, m, flag, arg);
    switch(flag) {
	case MIO_CLOSED:

	    log_debug2(ZONE, LOGT_IO, "[%s] io_select Socket %d close notification", ZONE, m->fd);
	    xhash_zap(cd->si->users, cd->client_id);
	    if (cd->state == state_AUTHD) {
		h = pthsock_make_route(NULL, jid_full(cd->session_id), cd->client_id, "error");
		deliver(dpacket_new(h), cd->si->i);
	    }

	    if (cd->pre_auth_mp != NULL) {
		/* if there is a pre_auth queue still */
		mio_wbq q;

		while ((q = (mio_wbq)pth_msgport_get(cd->pre_auth_mp)) != NULL) {
		    log_debug2(ZONE, LOGT_IO, "[%s] freeing unsent packet due to disconnect with no auth: %s", ZONE, xmlnode_serialize_string(q->x, xmppd::ns_decl_list(), 0));
		    xmlnode_free(q->x);
		}

		pth_msgport_destroy(cd->pre_auth_mp);
		cd->pre_auth_mp = NULL;
	    } 
	    break;
	case MIO_ERROR:
	    while ((h = mio_cleanup(m)) != NULL)
		deliver_fail(dpacket_new(h), N_("Socket Error to Client"));

	    break;
	case MIO_XML_ROOT:
	    log_debug2(ZONE, LOGT_IO, "[%s] root received for %d: %s", ZONE, m->fd, xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));
	    to = xmlnode_get_attrib_ns(x, "to", NULL);
	    cd->sending_id = jid_new(cd->m->p, to);

	    /* check for XMPP version attribute */
	    version = j_atoi(xmlnode_get_attrib_ns(x, "version", NULL), 0);

	    /* check for a matching alias or use default alias */
	    log_debug2(ZONE, LOGT_IO, "[%s] Recieved connection to: %s", ZONE, jid_full(cd->sending_id));
	    alias = static_cast<char*>(xhash_get(cd->si->aliases, to));
	    alias = alias ? alias : static_cast<char*>(xhash_get(cd->si->aliases, "default"));

	    /* set host to that alias, or to the given host */
	    cd->session_id = alias ? jid_new(m->p, alias) : cd->sending_id;

	    /* if we are using an alias, set the alias flag */
	    if (j_strcmp(jid_full(cd->session_id), jid_full(cd->sending_id)) != 0)
		cd->aliased = 1;
	    if (cd->aliased)
		log_debug2(ZONE, LOGT_SESSION, "[%s] using alias %s --> %s", ZONE, jid_full(cd->sending_id), jid_full(cd->session_id));

	    /* write header */
	    h = xstream_header(NULL, jid_full(cd->session_id));
	    cd->sid = pstrdup(m->p, xmlnode_get_attrib_ns(h, "id", NULL));
	    /* XXX hack in the style that jabber.com uses for flash mode support */
	    if (j_strcmp(xmlnode_get_namespace(x), NS_FLASHSTREAM) == 0) {
		h = xmlnode_new_tag_pool_ns(xmlnode_pool(h), "stream", "flash", NS_FLASHSTREAM);
		xmlnode_put_attrib_ns(h, "id", NULL, NULL, cd->sid); 
		xmlnode_put_attrib_ns(h, "from", NULL, NULL, jid_full(cd->session_id));
		xmlnode_put_attrib_ns(h, "xmlns", NS_XMLNS, NULL, NS_SERVER);
		xmlnode_put_attrib_ns(h, "stream", NS_XMLNS, "xmlns", NS_STREAM);
	    }
	    if (version>=1) {
		xmlnode_put_attrib_ns(h, "version", NULL, NULL, "1.0");
	    }
	    mio_write_root(m, h, 1);

	    if (cd->session_id == NULL) {
		/* they didn't send a to="" and no valid alias */
		mio_write(m, NULL, "<stream:error><improper-addressing xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Did not specify a valid to argument</text></stream:error></stream:stream>", -1);
		mio_close(m);
	    }

	    /* send stream features for XMPP version 1.0 streams */
	    if (version>=1) {
		xmlnode features = xmlnode_new_tag_ns("features", "stream", NS_STREAM);
		/* TLS possible on this connection? */
		if (mio_ssl_starttls_possible(m, cd->session_id->server)) {
		    xmlnode starttls = NULL;

		    starttls = xmlnode_insert_tag_ns(features, "starttls", NULL, NS_XMPP_TLS);
		}

		/* advertise registration of accounts? */
		if (cd->si->register_feature != 0) {
		    xmlnode register_element = NULL;

		    register_element = xmlnode_insert_tag_ns(features, "register", NULL, NS_REGISTER_FEATURE);
		}

		/* Non-SASL Authentication XEP-0078 */
		xmlnode_insert_tag_ns(features, "auth", NULL, NS_IQ_AUTH);

		/* send the stream:features */
		mio_write(m, features, NULL, 0);
	    }

	    xmlnode_free(x);
	    break;
	case MIO_XML_NODE:
	    /* make sure alias is upheld */
	    if (cd->aliased) {
		jid j = jid_new(xmlnode_pool(x), xmlnode_get_attrib_ns(x, "to", NULL));
		if (j != NULL && j_strcmp(j->server, cd->sending_id->server) == 0) {
		    jid_set(j, cd->session_id->server, JID_SERVER);
		    xmlnode_put_attrib_ns(x, "to", NULL, NULL, jid_full(j));
		}
		j = jid_new(xmlnode_pool(x), xmlnode_get_attrib_ns(x, "from", NULL));
		if (j != NULL && j_strcmp(j->server, cd->sending_id->server) == 0) {
		    jid_set(j, cd->session_id->server, JID_SERVER);
		    xmlnode_put_attrib_ns(x, "from", NULL, NULL, jid_full(j));
		}
	    }

	    cd = (cdata)arg;
	    if (cd->state == state_UNKNOWN) {
		/* only allow auth and registration queries at this point */
		xmlnode q_auth = xmlnode_get_list_item(xmlnode_get_tags(x, "auth:query", cd->si->std_namespace_prefixes), 0);
		xmlnode q_register = xmlnode_get_list_item(xmlnode_get_tags(x, "register:query", cd->si->std_namespace_prefixes), 0);
		if (j_strcmp(xmlnode_get_localname(x), "starttls") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_XMPP_TLS) == 0) {
		    /* starting TLS possible? */
		    if (mio_ssl_starttls_possible(m, cd->session_id->server)) {
			/* ACK the start */
			xmlnode proceed = xmlnode_new_tag_ns("proceed", NULL, NS_XMPP_TLS);
			mio_write(m, proceed, NULL, 0);

			/* start TLS on this connection */
			if (mio_xml_starttls(m, 0, cd->session_id->server) != 0) {
			    /* starttls failed */
			    mio_close(m);
			}
		    } else {
			/* NACK */
			mio_write(m, NULL, "<failure xmlns='" NS_XMPP_TLS "'/></stream:stream>", -1);
			mio_close(m);
		    }

		    /* free the <starttls/> element and return */
		    xmlnode_free(x);
		    return;
		} else if (q_auth == NULL && q_register == NULL) {
		    mio_wbq q;
		    /* queue packet until authed */
		    q = static_cast<mio_wbq>(pmalloco(xmlnode_pool(x), sizeof(_mio_wbq)));
		    q->x = x;
		    pth_msgport_put(cd->pre_auth_mp, reinterpret_cast<pth_message_t*>(q));
		    return;
		} else if (q_auth != NULL) {
		    if (j_strcmp(xmlnode_get_attrib_ns(x, "type", NULL), "set") == 0) {
			/* if we are authing against the server */
			xmlnode_put_attrib_ns(xmlnode_get_list_item(xmlnode_get_tags(q_auth, "auth:digest", cd->si->std_namespace_prefixes), 0), "sid", NULL, NULL, cd->sid);
			cd->auth_id = pstrdup(m->p, xmlnode_get_attrib_ns(x, "id", NULL));
			if (cd->auth_id == NULL) {
			    cd->auth_id = pstrdup(m->p, "pthsock_client_auth_ID");
			    xmlnode_put_attrib_ns(x, "id", NULL, NULL, "pthsock_client_auth_ID");
			}
			jid_set(cd->session_id, xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "auth:query/auth:username", cd->si->std_namespace_prefixes), 0)), JID_USER);
			jid_set(cd->session_id, xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "auth:query/auth:resource", cd->si->std_namespace_prefixes), 0)), JID_RESOURCE);

			x = pthsock_make_route(x, jid_full(cd->session_id), cd->client_id, "auth");
			deliver(dpacket_new(x), cd->si->i);
		    } else if(j_strcmp(xmlnode_get_attrib_ns(x, "type", NULL), "get") == 0) {
			/* we are just doing an auth get */
			/* just deliver the packet */
			jid_set(cd->session_id, xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "auth:query/auth:username", cd->si->std_namespace_prefixes), 0)), JID_USER);
			x = pthsock_make_route(x, jid_full(cd->session_id), cd->client_id, "auth");
			deliver(dpacket_new(x), cd->si->i);
		    }
		} else if (q_register != NULL) {
		    jid_set(cd->session_id, xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(x, "register:query/register:username", cd->si->std_namespace_prefixes), 0)), JID_USER);
		    x = pthsock_make_route(x, jid_full(cd->session_id), cd->client_id, "auth");
		    deliver(dpacket_new(x), cd->si->i);
		}
	    } else {
		/* normal delivery of packets after authed */
		x = pthsock_make_route(x, jid_full(cd->session_id), cd->client_id, NULL);
		deliver(dpacket_new(x), cd->si->i);
		cd->last_activity = time(NULL);
	    }
	    break;
    }
}


static void pthsock_client_listen(mio m, int flag, void *arg, xmlnode x, char* unused1, int unused2) {
    smi s__i = static_cast<smi>(arg);
    cdata cd;

    if (flag != MIO_NEW)
        return;

    s__i = (smi)arg;
    cd = pthsock_client_cdata(m, s__i);
    xhash_put(cd->si->users, cd->client_id, cd);
    mio_reset(m, pthsock_client_read, (void*)cd);
}


static void _pthsock_client_timeout(xht h, const char *key, void *data, void *arg) {
    time_t timeout;
    cdata cd = (cdata)data;
    if (cd->state == state_AUTHD) 
        return;

    timeout = time(NULL) - cd->si->auth_timeout;
    log_debug2(ZONE, LOGT_IO, "[%s] timeout: %d, connect time %d: fd %d", ZONE, timeout, cd->connect_time, cd->m->fd);

    if (cd->connect_time < timeout) {
        mio_write(cd->m, NULL, "<stream:error><connection-timeout xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Timeout waiting for authentication</text></stream:error></stream:stream>", -1);
        xhash_zap(cd->si->users, mio_ip(cd->m));
        mio_close(cd->m);
    }
}

/* auth timeout beat function */
static result pthsock_client_timeout(void *arg) {
    smi s__i = (smi)arg;

    if(s__i->users == NULL)
        return r_UNREG;

    xhash_walk(s__i->users, _pthsock_client_timeout, NULL);
    return r_DONE;
}

static void _pthsock_client_heartbeat(xht h, const char *key, void *data, void *arg) {
    time_t skipbeat;
    cdata cd = (cdata)data;

    skipbeat = time(NULL) - cd->si->heartbeat;
    if (cd->state == state_AUTHD
	    && cd->last_activity < skipbeat) {
       log_debug2(ZONE, LOGT_IO, "[%s] heartbeat on fd %d", ZONE, cd->m->fd);
       mio_write(cd->m, NULL, " \n", -1);
    }
}

/* auth timeout beat function */
static result pthsock_client_heartbeat(void *arg) {
    smi s__i = (smi)arg;

    if (s__i->users == NULL)
        return r_UNREG;

    xhash_walk(s__i->users, _pthsock_client_heartbeat, NULL);
    return r_DONE;
}


static void _pthsock_client_shutdown(xht h, const char *key, void *data, void *arg) {
    cdata cd = (cdata)data;
    log_debug2(ZONE, LOGT_CLEANUP, "[%s] closing down user %s from ip: %s", ZONE, jid_full(cd->session_id), mio_ip(cd->m));
    mio_close(cd->m);
}

/* cleanup function */
static void pthsock_client_shutdown(void *arg) {
    smi s__i = (smi)arg;
    xmlnode_free(s__i->cfg);
    log_debug2(ZONE, LOGT_CLEANUP, "[%s] Shutting Down", ZONE);
    xhash_walk(s__i->users, _pthsock_client_shutdown, NULL);
    xhash_free(s__i->users);
    s__i->users = NULL;
    if (s__i->aliases)
	xhash_free(s__i->aliases);
}

/* everything starts here */
extern "C" void pthsock_client(instance i, xmlnode x) {
    smi s__i;
    xdbcache xc;
    xmlnode cur;
    int set_rate = 0; /* Default false; did they want to change the rate parameters */
    int rate_time, rate_points;
    char *host;
    struct karma *k = karma_new(i->p); /* Get new inialized karma */
    int set_karma = 0; /* Default false; Did they want to change the karma parameters */
    char const* tls_config_element_name = "tls";
    xmlnode_list_item item = NULL;

    log_debug2(ZONE, LOGT_INIT, "[%s] pthsock_client loading", ZONE);

    s__i               = static_cast<smi>(pmalloco(i->p, sizeof(_smi)));
    s__i->auth_timeout = DEFAULT_AUTH_TIMEOUT;
    s__i->heartbeat    = DEFAULT_HEARTBEAT;
    s__i->i            = i;
    s__i->aliases      = xhash_new(7);
    s__i->users        = xhash_new(503);
    s__i->std_namespace_prefixes = xhash_new(17);
    s__i->register_feature = 1;

    xhash_put(s__i->std_namespace_prefixes, "", const_cast<char*>(NS_SERVER));
    xhash_put(s__i->std_namespace_prefixes, "auth", const_cast<char*>(NS_AUTH));
    xhash_put(s__i->std_namespace_prefixes, "pthcsock", const_cast<char*>(NS_JABBERD_CONFIG_PTHCSOCK));
    xhash_put(s__i->std_namespace_prefixes, "register", const_cast<char*>(NS_REGISTER));

    /* get the config */
    xc = xdb_cache(i);
    s__i->cfg = xdb_get(xc, jid_new(xmlnode_pool(x), "config@-internal"), NS_JABBERD_CONFIG_PTHCSOCK);

    s__i->host = host = i->id;

    for (cur = xmlnode_get_firstchild(s__i->cfg); cur != NULL; cur = cur->next) {
        if(cur->type != NTYPE_TAG) 
            continue;
	if (j_strcmp(xmlnode_get_namespace(cur), NS_JABBERD_CONFIG_PTHCSOCK) != 0)
	    continue;
        
        if (j_strcmp(xmlnode_get_localname(cur), "alias") == 0) {
           char *host, *to;
           if ((to = xmlnode_get_attrib_ns(cur, "to", NULL)) == NULL) 
               continue;

           host = xmlnode_get_data(cur);
           if (host != NULL) {
               xhash_put(s__i->aliases, host, to);
           } else {
               xhash_put(s__i->aliases, "default", to);
           }
        } else if(j_strcmp(xmlnode_get_localname(cur), "authtime") == 0) {
            s__i->auth_timeout = j_atoi(xmlnode_get_data(cur), 0);
        } else if(j_strcmp(xmlnode_get_localname(cur), "heartbeat") == 0) {
            s__i->heartbeat = j_atoi(xmlnode_get_data(cur), 0);
        } else if(j_strcmp(xmlnode_get_localname(cur), "rate") == 0) {
            rate_time   = j_atoi(xmlnode_get_attrib_ns(cur, "time", NULL), 0);
            rate_points = j_atoi(xmlnode_get_attrib_ns(cur, "points", NULL), 0);
            set_rate = 1; /* set to true */
        } else if(j_strcmp(xmlnode_get_localname(cur), "karma") == 0) {
            k->val     = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(cur, "pthcsock:init", s__i->std_namespace_prefixes), 0)), KARMA_INIT);
            k->max     = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(cur, "pthcsock:max", s__i->std_namespace_prefixes), 0)), KARMA_MAX);
            k->inc     = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(cur, "pthcsock:inc", s__i->std_namespace_prefixes), 0)), KARMA_INC);
            k->dec     = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(cur, "pthcsock:dec", s__i->std_namespace_prefixes), 0)), KARMA_DEC);
            k->restore = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(cur, "pthcsock:restore", s__i->std_namespace_prefixes), 0)), KARMA_RESTORE);
            k->penalty = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(cur, "pthcsock:penalty", s__i->std_namespace_prefixes), 0)), KARMA_PENALTY);
            k->reset_meter = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(cur, "pthcsock:resetmeter", s__i->std_namespace_prefixes), 0)), KARMA_RESETMETER);
            set_karma = 1; /* set to true */
        } else if (j_strcmp(xmlnode_get_localname(cur), "noregister") == 0) {
	    s__i->register_feature = 0;
	}
    }

    /* start listening */
    for (item = xmlnode_get_tags(s__i->cfg, "pthcsock:ip", s__i->std_namespace_prefixes); item != NULL; item = item->next) {
	mio m;
	m = mio_listen(j_atoi(xmlnode_get_attrib_ns(item->node, "port", NULL), 5222), xmlnode_get_data(item->node), pthsock_client_listen, (void*)s__i, MIO_LISTEN_XML);
	if(m == NULL)
	    return;

	/* Set New rate and points */
	if(set_rate == 1) mio_rate(m, rate_time, rate_points);
	/* Set New karma values */
	if(set_karma == 1) mio_karma2(m, k);
    }

    item = xmlnode_get_tags(s__i->cfg, "pthcsock:tls", s__i->std_namespace_prefixes);
    if (item == NULL) {
	item = xmlnode_get_tags(s__i->cfg, "pthcsock:ssl", s__i->std_namespace_prefixes);
	if (item != NULL)
	    log_warn(NULL, "Processing legacy <ssl/> element(s) inside pthsock_client configuration. The element has been renamed to <tls/>.");
    }

    /* listen on TLS sockets */
    for (; item != NULL; item = item->next) {
	mio m;
	mio_handlers mh;

	mh = mio_handlers_new(MIO_SSL_READ, MIO_SSL_WRITE, MIO_XML_PARSER);
	mh->accepted = MIO_SSL_ACCEPTED;
	m = mio_listen(j_atoi(xmlnode_get_attrib_ns(item->node, "port", NULL), 5223), xmlnode_get_data(item->node), pthsock_client_listen, (void*)s__i, mh);
	if (m == NULL)
	    return;
	/* Set New rate and points */
	if (set_rate == 1)
	    mio_rate(m, rate_time, rate_points);
	/* set karma valuse */
	if (set_karma == 1)
	    mio_karma2(m, k);
    }

    /* register data callbacks */
    register_phandler(i, o_DELIVER, pthsock_client_packets, (void*)s__i);
    pool_cleanup(i->p, pthsock_client_shutdown, (void*)s__i);
    if (s__i->auth_timeout)
        register_beat(5, pthsock_client_timeout, (void*)s__i);

    if (s__i->heartbeat) {
        log_debug2(ZONE, LOGT_INIT, "Registering heartbeat: %d", s__i->heartbeat);
        /* Register a heartbeat to catch dead sockets. */
        register_beat(s__i->heartbeat, pthsock_client_heartbeat, (void*)s__i);
    }
}
