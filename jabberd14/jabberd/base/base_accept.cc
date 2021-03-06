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
 * @brief opens a socket to handle incoming connections using the component
 * protocol defined in XEP-0114
 */

#include "jabberd.h"

#include <hash.hh>
#include <messages.hh>
#include <namespaces.hh>

#define A_ERROR -1
#define A_READY 1

typedef struct jqueue_struct {
    int stamp;
    xmlnode x;
    struct jqueue_struct *next;
} * jqueue, _jqueue;

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
    jqueue q;
    std::set<std::string>
        *dynamic_routings; /**< hostnames the peer has dynamically routed to
                              him, need to unregister on connection close */
} * accept_instance, _accept_instance;

static void base_accept_queue(accept_instance ai, xmlnode x) {
    jqueue q;
    if (ai == NULL || x == NULL)
        return;

    q = static_cast<jqueue>(pmalloco(xmlnode_pool(x), sizeof(_jqueue)));
    q->stamp = time(NULL);
    q->x = x;
    q->next = ai->q;
    ai->q = q;
}

/* Write packets to a xmlio object */
static result base_accept_deliver(instance i, dpacket p, void *arg) {
    accept_instance ai = (accept_instance)arg;

    /* Insert the message into the write_queue if we don't have a MIO socket
     * yet.. */
    if (ai->state == A_READY) {
        mio_write(ai->m, p->x, NULL, 0);
        return r_DONE;
    }

    base_accept_queue(ai, p->x);
    return r_DONE;
}

static void base_accept_unregister_dynamics(accept_instance ai) {
    // sanity check
    if (!ai)
        return;

    // unregister the dynamic routings
    if (ai->dynamic_routings) {
        for (std::set<std::string>::const_iterator p =
                 ai->dynamic_routings->begin();
             p != ai->dynamic_routings->end(); ++p) {
            log_notice(ai->i->id, "unregistering dynamic routing for '%s'",
                       p->c_str());
            unregister_instance(ai->i, p->c_str());
        }

        delete ai->dynamic_routings;
        ai->dynamic_routings = NULL;
    }

    // create new set for future dynamic routings
    ai->dynamic_routings = new std::set<std::string>();
}

/* Handle incoming packets from the xstream associated with an MIO object */
static void base_accept_process_xml(mio m, int state, void *arg, xmlnode x,
                                    char *unused1, int unused2) {
    accept_instance ai = (accept_instance)arg;
    xmlnode cur, off;
    jqueue q, q2;
    jpacket jp;
    char const *pwdsent;
    xmppd::sha1 pwdcheck;

    log_debug2(ZONE, LOGT_XML, "process XML: m:%X state:%d, arg:%X, x:%X", m,
               state, arg, x);

    switch (state) {
        case MIO_XML_ROOT:
            /* Send header w/ proper namespace, using instance i */
            cur = xstream_header(NULL, ai->i->id);
            /* Save stream ID for auth'ing later */
            ai->id = pstrdup(ai->p, xmlnode_get_attrib_ns(cur, "id", NULL));
            mio_write_root(m, cur, 2);
            break;

        case MIO_XML_NODE:
            /* If aio has been authenticated previously, go ahead and deliver
             * the packet */
            if (ai->state == A_READY && m == ai->m) {
                /* if we are supposed to be careful about what comes from this
                 * socket */
                if (ai->restrict_var) {
                    jp = jpacket_new(x);
                    if (jp->type == JPACKET_UNKNOWN || jp->to == NULL ||
                        jp->from == NULL ||
                        !deliver_is_delivered_to(jp->from->get_domain(),
                                                 ai->i)) {
                        jutil_error_xmpp(x, XTERROR_INTERNAL);
                        mio_write(m, x, NULL, 0);
                        return;
                    }
                }

                // create a deliverable packet from the stanza we got
                dpacket p = dpacket_new(x);

                // check if this is a routing update we got
                if (p && p->type == p_XDB && p->id &&
                    p->id->get_domain() == "-internal" && p->id->has_node()) {
                    // check for host@-internal
                    if (p->id->get_node() == "host" && p->id->has_resource()) {
                        ai->dynamic_routings->insert(p->id->get_resource());
                    }

                    // XXX might check for unhost as well
                }

                deliver(p, ai->i);
                return;
            }

            /* only other packets are handshakes */
            if (j_strcmp(xmlnode_get_localname(x), "handshake") != 0 ||
                j_strcmp(xmlnode_get_namespace(x), NS_SERVER) != 0) {
                mio_write(m, NULL,
                          "<stream:error><not-authorized "
                          "xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text "
                          "xmlns='urn:ietf:params:xml:ns:xmpp-streams' "
                          "xml:lang='en'>Must send handshake "
                          "first.</text></stream:error>",
                          -1);
                mio_close(m);
                break;
            }

            /* Create and check a SHA hash of this instance's password & SID */
            if (ai->id)
                pwdcheck.update(ai->id);
            if (ai->secret)
                pwdcheck.update(ai->secret);
            pwdsent = xmlnode_get_data(x);
            if (!pwdsent || pwdcheck.final_hex() != std::string(pwdsent)) {
                mio_write(
                    m, NULL,
                    "<stream:error><not-authorized "
                    "xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text "
                    "xmlns='urn:ietf:params:xml:ns:xmpp-streams' "
                    "xml:lang='en'>Invalid handshake</text></stream:error>",
                    -1);
                mio_close(m);
                break;
            }

            /* Send a handshake confirmation */
            mio_write(m, NULL, "<handshake/>", -1);

            /* check for existing conenction and kill it */
            if (ai->m != NULL) {
                log_warn(ai->i->id,
                         "Socket override by another connection from %s",
                         mio_ip(m));
                mio_write(ai->m, NULL,
                          "<stream:error><conflict "
                          "xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text "
                          "xmlns='urn:ietf:params:xml:ns:xmpp-streams' "
                          "xml:lang='en'>Socket override by another "
                          "connection.</text></stream:error>",
                          -1);
                mio_close(ai->m);
            }

            /* hook us up! */
            ai->m = m;
            ai->state = A_READY;

            /* if offline, get anything stored and deliver */
            if (ai->offline != NULL) {
                off = xdb_get(ai->offline, ai->offjid, "base:accept:offline");
                for (cur = xmlnode_get_firstchild(off); cur != NULL;
                     cur = xmlnode_get_nextsibling(cur)) {
                    /* dup and deliver stored packets... XXX should probably
                     * handle NS_EXPIRE, I get lazy at 6am */
                    mio_write(m, xmlnode_dup(cur), NULL, 0);
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

            // if we are configured as uplink, request the routings to the other
            // instances of this process from our peer process
            if (deliver_is_uplink(ai->i)) {
                std::set<Glib::ustring> hosts_to_route =
                    deliver_routed_hosts(p_NORM, ai->i);

                for (std::set<Glib::ustring>::const_iterator p =
                         hosts_to_route.begin();
                     p != hosts_to_route.end(); ++p) {
                    log_debug2(
                        ZONE, LOGT_DYNAMIC,
                        "base_accept is uplink. Sending routing request: %s",
                        p->c_str());
                    xmlnode route_stanza =
                        xmlnode_new_tag_ns("xdb", NULL, NS_SERVER);
                    xmlnode_put_attrib_ns(route_stanza, "ns", NULL, NULL, "");
                    xmlnode_put_attrib_ns(route_stanza, "from", NULL, NULL,
                                          ai->i->id);
                    jid magic_jid =
                        jid_new(xmlnode_pool(route_stanza), "host@-internal");
                    jid_set(magic_jid, p->c_str(), JID_RESOURCE);
                    xmlnode_put_attrib_ns(route_stanza, "to", NULL, NULL,
                                          jid_full(magic_jid));
                    mio_write(m, route_stanza, NULL, 0);
                }
            }

            break;

        case MIO_ERROR:
            /* make sure it's the important one */
            if (m != ai->m)
                return;

            ai->state = A_ERROR;

            log_notice(ai->i->id, "Connection to peer had an error");

            /* clean up any tirds */
            while ((cur = mio_cleanup(m)) != NULL)
                deliver_fail(dpacket_new(cur), N_("External Server Error"));

            // unregister dynamic routings to peer
            base_accept_unregister_dynamics(ai);

            return;

        case MIO_CLOSED:
            /* make sure it's the important one */
            if (m != ai->m)
                return;

            log_notice(ai->i->id, "Connection to peer has been closed");
            ai->m = NULL;
            ai->state = A_ERROR;

            // unregister dynamic routings to peer
            base_accept_unregister_dynamics(ai);

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

    if (ai->offline == NULL) {
        snprintf(errmsg, sizeof(errmsg),
                 messages_get(xmlnode_get_lang(x),
                              N_("Component '%s' is not connected to server")),
                 ai->i == NULL ? "(NULL)"
                               : ai->i->id != NULL ? ai->i->id : "(null)");
        deliver_fail(dpacket_new(x), errmsg);
        return;
    }

    p = jpacket_new(x);
    switch (p->type) {
        case JPACKET_MESSAGE:
            /* XXX should probably handle offline events I guess, more lazy */
        case JPACKET_S10N:
            if (xdb_act_path(ai->offline, ai->offjid, "base:accept:offline",
                             "insert", NULL, NULL, x) == 0) {
                xmlnode_free(x);
                return;
            }
            break;
        default:
            break;
    }

    snprintf(errmsg, sizeof(errmsg),
             messages_get(xmlnode_get_lang(x),
                          N_("delivery to '%s': Internal Timeout")),
             ai->i == NULL ? "(NULL)"
                           : ai->i->id != NULL ? ai->i->id : "(null)");
    deliver_fail(dpacket_new(x), errmsg);
}

/* check the packet queue for stale packets */
static result base_accept_beat(void *arg) {
    accept_instance ai = (accept_instance)arg;
    jqueue bouncer, lastgood, cur, next;
    int now = time(NULL);

    cur = ai->q;
    bouncer = lastgood = NULL;
    while (cur != NULL) {
        if ((now - cur->stamp) <= ai->timeout) {
            lastgood = cur;
            cur = cur->next;
            continue;
        }

        /* timed out sukkah! */
        next = cur->next;
        if (lastgood == NULL)
            ai->q = next;
        else
            lastgood->next = next;

        /* place in a special queue to bounce later on */
        cur->next = bouncer;
        bouncer = cur;

        cur = next;
    }

    while (bouncer != NULL) {
        next = bouncer->next;
        base_accept_offline(ai, bouncer->x);
        bouncer = next;
    }

    return r_DONE;
}

static void base_accept_send_routingupdate(accept_instance inst,
                                           char const *destination,
                                           int is_register) {
    xmlnode route_stanza = xmlnode_new_tag_ns("xdb", NULL, NS_SERVER);
    xmlnode_put_attrib_ns(route_stanza, "ns", NULL, NULL, "");
    xmlnode_put_attrib_ns(route_stanza, "from", NULL, NULL, inst->i->id);
    jid magic_jid =
        jid_new(xmlnode_pool(route_stanza),
                is_register ? "host@-internal" : "unhost@-internal");
    jid_set(magic_jid, destination, JID_RESOURCE);
    xmlnode_put_attrib_ns(route_stanza, "to", NULL, NULL, jid_full(magic_jid));
    mio_write(inst->m, route_stanza, NULL, 0);
}

/**
 * callback that gets notified if a new host is routed by this jabberd instance
 *
 * @param i the instance that (un)registered the host
 * @param destination the host that got (un)registered
 * @param is_register 0 for unregister, non-zero for register
 * @param arg the accept_instance that registered this callback
 */
static void base_accept_routingupdate(instance i, char const *destination,
                                      int is_register, void *arg) {
    accept_instance inst = static_cast<accept_instance>(arg);
    // sanity check
    if (!inst || !destination)
        return;

    // we only care for routingupdates if we are configured to be the uplink
    if (!deliver_is_uplink(inst->i))
        return;

    // we do not forward default routings
    if (std::string("*") == destination)
        return;

    // do not route back updates if both sides feel being an uplink
    if (inst->i == i)
        return;

    // and we have to have an established connection
    if (!inst->m || inst->state != A_READY)
        return;

    log_debug2(ZONE, LOGT_DYNAMIC,
               "base_accept is uplink and has to forward %s",
               is_register ? "host-command" : "unhost-command");
    base_accept_send_routingupdate(inst, destination, is_register);
}

static void _base_accept_freeing_instance(void *arg) {
    accept_instance inst = static_cast<accept_instance>(arg);

    if (!inst)
        return;

    if (inst->dynamic_routings)
        delete inst->dynamic_routings;
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
    xhash_put(namespaces, "", const_cast<char *>(NS_JABBERD_CONFIGFILE));
    secret = xmlnode_get_data(
        xmlnode_get_list_item(xmlnode_get_tags(x, "secret", namespaces), 0));
    ip = xmlnode_get_data(
        xmlnode_get_list_item(xmlnode_get_tags(x, "ip", namespaces), 0));
    port = j_atoi(xmlnode_get_data(xmlnode_get_list_item(
                      xmlnode_get_tags(x, "port", namespaces), 0)),
                  0);
    restrict_var = xmlnode_get_data(xmlnode_get_list_item(
                       xmlnode_get_tags(x, "restrict", namespaces), 0)) != NULL
                       ? 1
                       : 0;
    offline = xmlnode_get_data(xmlnode_get_list_item(
                  xmlnode_get_tags(x, "offline", namespaces), 0)) != NULL
                  ? 1
                  : 0;
    timeout = j_atoi(xmlnode_get_data(xmlnode_get_list_item(
                         xmlnode_get_tags(x, "timeout", namespaces), 0)),
                     10);
    xhash_free(namespaces);

    if (id == NULL) {
        log_debug2(ZONE, LOGT_INIT | LOGT_CONFIG,
                   "base_accept_config validating configuration...");
        if (port == 0 || secret == NULL) {
            xmlnode_put_attrib_ns(x, "error", NULL, NULL,
                                  "<accept> requires the following subtags: "
                                  "<port>, and <secret>");
            return r_ERR;
        }
        return r_PASS;
    }

    log_debug2(ZONE, LOGT_INIT | LOGT_CONFIG,
               "base_accept_config performing configuration %s\n",
               xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));

    /* Setup the default sink for this instance */
    inst =
        static_cast<accept_instance>(pmalloco(id->p, sizeof(_accept_instance)));
    inst->p = id->p;
    inst->i = id;
    inst->secret = secret;
    inst->ip = ip;
    inst->port = port;
    inst->timeout = timeout;
    inst->dynamic_routings = new std::set<std::string>();
    pool_cleanup(id->p, _base_accept_freeing_instance,
                 static_cast<void *>(inst));
    if (restrict_var)
        inst->restrict_var = 1;
    if (offline) {
        inst->offline = xdb_cache(id);
        inst->offjid = jid_new(id->p, id->id);
    }

    /* Start a new listening thread and associate this <listen> tag with it */
    if (mio_listen(inst->port, inst->ip, base_accept_process_xml, inst,
                   mio_handlers_new(NULL, NULL, MIO_XML_PARSER)) == NULL) {
        xmlnode_put_attrib_ns(
            x, "error", NULL, NULL,
            "<accept> unable to listen on the configured ip and port");
        return r_ERR;
    }

    /* Register a packet handler and cleanup heartbeat for this instance */
    register_phandler(id, o_DELIVER, base_accept_deliver, (void *)inst);

    // Register a handler that gets notified on newly available hosts
    register_routing_update_callback(NULL, base_accept_routingupdate,
                                     static_cast<void *>(inst));

    /* timeout check */
    register_beat(inst->timeout, base_accept_beat, (void *)inst);

    return r_DONE;
}

/**
 * register the accept base handler
 *
 * @param p memory pool used to register the configuration handler of this
 * handler (must be available for the livetime of jabberd)
 */
void base_accept(pool p) {
    log_debug2(ZONE, LOGT_INIT, "base_accept loading...\n");
    register_config(p, "accept", base_accept_config, NULL);
}
