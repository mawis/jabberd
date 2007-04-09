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
 * @file jabberd/deliver.cc
 * @brief implements the XML stanza routing of jabberd
 *
 * The jabberd execuatable is mainly a router for XML stanzas, that routes stanzas between the base handlers, that connect the components
 * of the jabberd server to this XML routing. Inside this file the XML routing inside the jabberd server is implemented.
 *
 * There are actually three routings, that are defined: One routing for &lt;log/&gt; stanzas (used to send log messages to
 * a component, that logs the message to a file or the syslog), the second for &lt;xdb/&gt; stanzas (used to abstract database
 * access into xdb handlers), and the third routing for other stanzas (&lt;route/&gt;, &lt;message/&gt;, &lt;presence/&gt;,
 * and &lt;iq/&gt;).
 *
 * The basic routing is defined on startup using the configuration file. &lt;xdb/&gt; sections in the configuration are registered in
 * the routing for &lt;xdb/&gt; stanzas, &lt;log/&gt; sections in the configuration are registered in the routing for
 * &lt;log/&gt; stanzas, &lt;service/&gt; sections are registered in the routing for the other stanzas.
 *
 * Routing is done based on the domain part of a JID. The components can be registered to get stanzas for domains. On startup
 * the component is registered for the domain contained in the value of the id attribute of the configuration file element as
 * well as for all domains configured with &lt;host/&gt; elements inside the section of the component. Where each &lt;host/&gt;
 * element contains a single additional domain, and an empty &lt;host/&gt; registers the component to be a default handler if
 * no other component has explicitly registered to handle the domain. (Additionally there is the &lt;uplink/&gt; element,
 * which is nearly the same as an empty &lt;host/&gt; element, but registers a routing not only in a single routing, but in
 * all three XML routings. To be more precise: It is the fallback if there is even no default component for a given routing.
 * There can be only one uplink in a single instance of jabberd.)
 *
 * After a component has started, it can register for additional routings using the register_instance() function, or unregister
 * an existing routing using the unregister_instance() function.
 */

/* WARNING: the comments in here are random ramblings across the timespan this file has lived, don't rely on them for anything except entertainment (and if this entertains you, heh, you need to get out more :)

<jer mode="pondering">

ok, the whole <xdb/> <log/> <service/> and id="" and <host/> have gotten us this far, barely, but it needs some rethought.

there seem to be four types of conversations, xdb, log, route, and normal packets
each type can be sub-divided based on different criteria, such as hostname, namespace, log type, etc.

to do this right, base modules need to be able to assert their own logic within the delivery process
and we need to do it efficiently
and logically, so the administrator is able to understand where the packets are flowing

upon startup, like normal configuration directive callbacks, base modules can register a filter config callback with an arg per-type (xdb/log/service)
configuration calls each one of those, which use the arg to identify the instance that they are within
this one is special, jabberd tracks which instances each callback is associated with based on 
during configuration, jabberd tracks which base modules were called
so during the configuration process, each base module registers a callback PER-INSTANCE that it's configured in

first, break down by
first step with a packet to be delivered is identify the instance it belongs to

filter_host
filter_ns
filter_logtype

it's an & operation, host & ns must have to match

first get type (xdb/log/svc)
then find which filters for the list of instances
then ask each filter to return a sub-set
after all the filters, deliver to the final instance(s)

what if we make <route/> addressing seperate, and only use the id="" for it?

we need to add a <drain> ... <drain> which matches any undelivered packet, and can send to another jabberd via accept/exec/stdout/etc
</jer>

<jer mode="pretty sure">

id="" is only required on services

HT host_norm
HT host_xdb
HT host_log
HT ns
ilist log_notice, log_alert, log_warning

to deliver the dpacket, first check the right host hashtable and get a list
second, if it's xdb or log, check the ns HT or log type list
find intersection of lists

if a host, ns, or type is used in any instance, it must be used in ALL of that type, or configuration error!

if intersection has multiple results, fail, or none, find uplink or fail

deliver()
	deliver_norm
		if(host_norm != NULL) ilista = host_norm(host)
	deliver_xdb
		if(host_xdb != NULL) ilista = host_xdb(host)
		if(ns != NULL) ilistb = ns(namespace)
		i = intersect(ilista, ilistb)
			if result multiple, return NULL
			if result single, return
			if result NULL, return uplink
		deliver_instance(i)
	deliver_log
		host_log, if logtype_flag switch on type
</jer> */

#include "jabberd.h"

int deliver__flag=0;	/**< 0 = pause delivery on startup and queue for later delivery, 1 = normal operation, -1 = shutdown: no delivery, no queueing */
pth_msgport_t deliver__mp=NULL;	/**< message port, that contains all queued messages for later delivery while ::deliver__flag = 0 */

/**
 * queue item for the list of queued messages for later delivery, used while ::deliver__flag = 0
 */
typedef struct deliver_mp_st {
    pth_message_t head;	/**< the standard pth message header */
    instance i;		/**< the sending instance */
    dpacket p;		/**< the queued packet */
} _deliver_msg,*deliver_msg;

/**
 * list of all instances of ::instance
 */
typedef struct ilist_struct {
    instance i;
    struct ilist_struct *next;
} *ilist, _ilist;

/**
 * add an ::instance to the list of all instances
 *
 * @param il the existing list
 * @param i the instance to be added
 * @return the new list
 */
static ilist ilist_add(ilist il, instance i) {
    ilist cur, ilnew;

    for(cur = il; cur != NULL; cur = cur->next)
        if(cur->i == i)
            return cur;

    ilnew = static_cast<ilist>(pmalloco(i->p, sizeof(_ilist)));
    ilnew->i = i;
    ilnew->next = il;
    return ilnew;
}

/**
 * remove an ::instance from the list of instances
 *
 * @param il the existing list
 * @param i the instance to be deleted
 * @return the new list
 */
static ilist ilist_rem(ilist il, instance i) {
    ilist cur;

    if(il == NULL) return NULL;

    if(il->i == i) return il->next;

    for(cur = il; cur->next != NULL; cur = cur->next)
        if(cur->next->i == i)
        {
            cur->next = cur->next->next;
            return il;
        }

    return il;
}

/* XXX handle removing things from the list too, yuck */

/* set up our global delivery logic tracking vars */

xht deliver__hnorm = NULL; /**< hosts for normal packets, important and most frequently used one */
xht deliver__hxdb = NULL; /**< host filters for xdb requests */
xht deliver__hlog = NULL; /**< host filters for logging */
xht deliver__ns = NULL; /**< namespace filters for xdb */
xht deliver__logtype = NULL; /**< log types, fixed set, but it's easier (wussier) to just be consistent and use a hashtable */

/* ilist deliver__all = NULL; / all instances - not used anymore!? */
instance deliver__uplink = NULL; /**< uplink instance, only one */

/**
 * utility to find the right routing hashtable based on type of a stanza
 *
 * @param ptype the ::type of a packet
 * @return the correct hashtable used for the routing of this stanza type
 */
static xht deliver_hashtable(ptype type) {
    switch(type)
    {
    case p_LOG:
        return deliver__hlog;
    case p_XDB:
        return deliver__hxdb;
    default:
        return deliver__hnorm;
    }
}

/**
 * utility to find the right ilist in the hashtable
 *
 * @param ht the hashtable for the routing of a stanzatype
 * @param key the domain to be looked up (or "*" if the default routing is searched)
 * @return the list of instances registered for this routing
 */
static ilist deliver_hashmatch(xht ht, char *key) {
    ilist l;
    l = static_cast<ilist>(xhash_get(ht, key));
    if (l == NULL) {
        l = static_cast<ilist>(xhash_get(ht, "*"));
    }
    return l;
}

/**
 * find and return the instance intersecting both lists, or react intelligently
 *
 * @param a first list of instances
 * @param b second list of instances
 * @return the ::instance, that is in both lists - or NULL if the intersection contains multiple instances - or the instance registered as uplink, if there was no match
 */
static instance deliver_intersect(ilist a, ilist b) {
    ilist cur = NULL, cur2;
    instance i = NULL;

    if(a == NULL)
        cur = b;
    if(b == NULL)
        cur = a;

    if(cur != NULL) /* we've only got one list */
    {
        if(cur->next != NULL)
            return NULL; /* multiple results is a failure */
        else
            return cur->i;
    }

    for(cur = a; cur != NULL; cur = cur->next)
    {
        for(cur2 = b; cur2 != NULL; cur2 = cur2->next)
        {
            if(cur->i == cur2->i) /* yay, intersection! */
            {
                if(i != NULL)
                    return NULL; /* multiple results is a failure */
                i = cur->i;
            }
        }
    }

    if(i == NULL) /* no match, use uplink */
        return deliver__uplink;

    return i;
}

/**
 * special case handler for xdb calls @-internal
 *
 * "-internal" is a special domain. Using config@-internal as JID a component can access the 
 * configuration file of jabberd. Using host@-internal or unhost@-internal a component can
 * register/unregister for the routing of a domain that is specified as the resource of the
 * JID.
 *
 * @TODO The whole thing is a bit hacky. As long as we are using this hack, we might
 * at least better use one of the RFC 2606 domains.
 *
 * @param p the packet to deliver
 * @param i the sender instance of the packet
 */
static void deliver_internal(dpacket p, instance i) {
    xmlnode x;
    char *ns = xmlnode_get_attrib_ns(p->x, "ns", NULL);

    log_debug2(ZONE, LOGT_DELIVER, "@-internal processing %s", xmlnode_serialize_string(p->x, xmppd::ns_decl_list(), 0));

    if(j_strcmp(p->id->user,"config") == 0) {
	/* config@-internal means it's a special xdb request to get data from the config file */
        for(x = xmlnode_get_firstchild(i->x); x != NULL; x = xmlnode_get_nextsibling(x)) {
	    if (j_strcmp(xmlnode_get_namespace(x), NS_JABBERD_CONFIGFILE) == 0)
		continue;

            /* insert results */
            xmlnode_insert_tag_node(p->x, x);
        }

        /* reformat packet as a reply */
        xmlnode_put_attrib_ns(p->x, "type", NULL, NULL, "result");
        jutil_tofrom(p->x);
        p->type = p_NORM;

        /* deliver back to the sending instance */
        deliver_instance(i, p);
        return;
    }

    if(j_strcmp(p->id->user,"host") == 0) {
	/* dynamic register_instance crap */
        register_instance(i,p->id->resource);
        return;
    }

    if(j_strcmp(p->id->user,"unhost") == 0) {
	/* dynamic register_instance crap */
        unregister_instance(i,p->id->resource); 
        return;
    }
}

/**
 * register this instance as a possible recipient of packets to this host
 *
 * @param i the instance to register
 * @param host the domain to register this instance for (or "*" to register as the default routing)
 */
void register_instance(instance i, char *host) {
    ilist l;
    xht ht = NULL;
    xht namespaces = NULL;
    register_notifier notify_callback = NULL;

    log_debug2(ZONE, LOGT_REGISTER, "Registering %s with instance %s", host, i->id);

    namespaces = xhash_new(3);
    xhash_put(namespaces, "", const_cast<char*>(NS_JABBERD_CONFIGFILE));

    pool temp_pool = pool_new();

    /* fail, since ns is required on every XDB instance if it's used on any one */
    if (i->type == p_XDB && deliver__ns != NULL && xmlnode_get_list_item(xmlnode_get_tags(i->x, "ns", namespaces, temp_pool), 0) == NULL) {
        fprintf(stderr, "Configuration Error!  If <ns> is used in any xdb section, it must be used in all sections for correct packet routing.");
        exit(1);
    }
    /* fail, since logtype is required on every LOG instance if it's used on any one */
    if (i->type == p_LOG && deliver__logtype != NULL && xmlnode_get_list_item(xmlnode_get_tags(i->x, "logtype", namespaces, temp_pool), 0) == NULL) {
        fprintf(stderr, "Configuration Error!  If <logtype> is used in any log section, it must be used in all sections for correct packet routing.");
        exit(1);
    }
    xhash_free(namespaces);
    pool_free(temp_pool);
    temp_pool = NULL;

    /* inform the instance about the newly routed domain */
    for (notify_callback = i->routing_update_callbacks; notify_callback != NULL; notify_callback = notify_callback->next) {
	(notify_callback->callback)(i, host, 1, notify_callback->arg);
    }

    ht = deliver_hashtable(i->type);
    l = static_cast<ilist>(xhash_get(ht, host));
    l = ilist_add(l, i);
    xhash_put(ht, pstrdup(i->p,host), (void *)l);
}

/**
 * unregister an instance as a possible recipient of packets for a domain
 *
 * @param i the instance to unregister
 * @param host the domain to unregister (or "*" to unregister as the default routing)
 */
void unregister_instance(instance i, char *host) {
    ilist l;
    xht ht;
    register_notifier notify_callback = NULL;

    log_debug2(ZONE, LOGT_REGISTER, "Unregistering %s with instance %s",host,i->id);

    ht = deliver_hashtable(i->type);
    l = static_cast<ilist>(xhash_get(ht, host));
    l = ilist_rem(l, i);
    if (l == NULL)
        xhash_zap(ht, host);
    else
        xhash_put(ht, pstrdup(i->p,host), (void *)l);

    /* inform the instance about the domain, that is not routed anymore */
    for (notify_callback = i->routing_update_callbacks; notify_callback != NULL; notify_callback = notify_callback->next) {
	(notify_callback->callback)(i, host, 0, notify_callback->arg);
    }

}

/**
 * handler for the &lt;host/&gt; configuration element
 *
 * @param i the instance the element is read for
 * @param x the configuration element
 * @param arg unused/ignored
 * @return r_DONE if the instance is registered, r_ERR on error, r_PASS if no instance provided by the caller
 */
static result deliver_config_host(instance i, xmlnode x, void *arg) {
    char *host;
    int c;

    if (i == NULL)
        return r_PASS;

    host = xmlnode_get_data(x);
    if (host == NULL) {
        register_instance(i, "*");
        return r_DONE;
    }

    for (c = 0; host[c] != '\0'; c++) {
        if (isspace((int)host[c])) {
            xmlnode_put_attrib_ns(x, "error", NULL, NULL, "The host tag contains illegal whitespace.");
            return r_ERR;
        }
    }

    register_instance(i, host);

    return r_DONE;
}

/**
 * handler for the &lt;ns/&gt; configuration element
 *
 * @param i the instance the element is read for
 * @param x the configuration element
 * @param arg unused/ignored
 * @return r_DONE if the instance is registered, r_ERR on error, r_PASS if no instance provided by the caller
 */
static result deliver_config_ns(instance i, xmlnode x, void *arg) {
    ilist l;
    char *ns, star[] = "*";

    if (i == NULL)
        return r_PASS;

    if (i->type != p_XDB)
        return r_ERR;

    ns = xmlnode_get_data(x);
    if (ns == NULL)
        ns = pstrdup(xmlnode_pool(x),star);

    log_debug2(ZONE, LOGT_INIT|LOGT_STORAGE|LOGT_REGISTER, "Registering namespace %s with instance %s",ns,i->id);

    if (deliver__ns == NULL)
	deliver__ns = xhash_new(401);

    l = static_cast<ilist>(xhash_get(deliver__ns, ns));
    l = ilist_add(l, i);
    xhash_put(deliver__ns, ns, (void *)l);

    return r_DONE;
}

/**
 * handler for the &lt;logtype/&gt; configuration element
 * 
 * @param i the instance the element is read for
 * @param x the configuration element
 * @param arg unused/ignored
 * @return r_DONE if the instance is registered, r_ERR on error, r_PASS if no instance provided by the caller
 */
static result deliver_config_logtype(instance i, xmlnode x, void *arg) {
    ilist l;
    char *type, star[] = "*";

    if (i == NULL)
        return r_PASS;

    if (i->type != p_LOG)
        return r_ERR;

    type = xmlnode_get_data(x);
    if (type == NULL)
        type = pstrdup(xmlnode_pool(x),star);

    log_debug2(ZONE, LOGT_REGISTER, "Registering logtype %s with instance %s",type,i->id);

    if (deliver__logtype == NULL)
	deliver__logtype = xhash_new(401);

    l = static_cast<ilist>(xhash_get(deliver__logtype, type));
    l = ilist_add(l, i);
    xhash_put(deliver__logtype, type, (void *)l);

    return r_DONE;
}

/**
 * handler for the &lt;uplink/&gt; configuration element
 * 
 * @param i the instance the element is read for
 * @param x the configuration element
 * @param arg unused/ignored
 * @return r_DONE if the instance is registered, r_ERR on error, r_PASS if no instance provided by the caller
 */
static result deliver_config_uplink(instance i, xmlnode x, void *arg) {
    if (i == NULL)
        return r_PASS;

    if (deliver__uplink != NULL)
        return r_ERR;

    deliver__uplink = i;
    return r_DONE;
}

/**
 * after deliver__flag switched to 1, we have to notify the instances about hosts already routed
 *
 * this is used as a xhash_walker that walks the routing hashes
 *
 * @param h unused
 * @param key the host that is routed
 * @param value ilist for this host
 * @param arg unused
 */
static void _deliver_notify_walker(xht h, const char *key, void *value, void *arg) {
    ilist instance_list = (ilist)value;

    /* sanity check */
    if (key == NULL)
	return;

    while (instance_list != NULL) {
	register_notifier iter = NULL;

	/* sanity check */
	if (instance_list->i == NULL)
	    continue;

	/* fire all callbacks */
	for (iter = instance_list->i->routing_update_callbacks; iter != NULL; iter = iter->next) {
	    (iter->callback)(instance_list->i, key, 1, iter->arg);
	}

	instance_list = instance_list->next;
    }
}

/**
 * deliver a ::dpacket to an ::instance using the configured XML routings
 *
 * @param p the packet that should be delivered
 * @param i the instance of the sender (!) of the packet
 */
void deliver(dpacket p, instance i) {
    ilist a, b;

    if(deliver__flag == 1 && p == NULL && i == NULL) {
	/* send notifies for already configured routings */
	xhash_walk(deliver_hashtable(p_LOG), _deliver_notify_walker, NULL);
	xhash_walk(deliver_hashtable(p_XDB), _deliver_notify_walker, NULL);
	xhash_walk(deliver_hashtable(p_NORM), _deliver_notify_walker, NULL);

	/* begin delivery of postponed messages */
        deliver_msg d;
        while ((d=(deliver_msg)pth_msgport_get(deliver__mp))!=NULL) {
            deliver(d->p,d->i);
        }
        pth_msgport_destroy(deliver__mp);
        deliver__mp = NULL;
        deliver__flag = -1; /* disable all queueing crap */
    }

    /* Ensure the packet is valid */
    if (p == NULL)
	 return;

    /* catch the @-internal xdb crap */
    if (p->type == p_XDB && *(p->host) == '-') {
        deliver_internal(p, i);
        return;
    }

    if (deliver__flag == 0) {
	/* postpone delivery till later */
        deliver_msg d = static_cast<deliver_msg>(pmalloco(xmlnode_pool(p->x), sizeof(_deliver_msg)));
        
        if (deliver__mp == NULL)
            deliver__mp = pth_msgport_create("deliver__");
        
        d->i = i;
        d->p = p;
        
        pth_msgport_put(deliver__mp, reinterpret_cast<pth_message_t*>(d));
        return;
    }

    log_debug2(ZONE, LOGT_DELIVER, "DELIVER %d:%s %s", p->type, p->host, xmlnode_serialize_string(p->x, xmppd::ns_decl_list(), 0));

    b = NULL;
    a = deliver_hashmatch(deliver_hashtable(p->type), p->host);
    if (p->type == p_XDB)
        b = deliver_hashmatch(deliver__ns, xmlnode_get_attrib_ns(p->x, "ns", NULL));
    else if(p->type == p_LOG)
        b = deliver_hashmatch(deliver__logtype, xmlnode_get_attrib_ns(p->x, "type", NULL));
    deliver_instance(deliver_intersect(a, b), p);
}


/**
 * util to check and see which instance this hostname is going to get mapped to for normal packets
 *
 * @param host the hostname to get checked
 * @return the instance packets of this host get mapped to
 */
instance deliver_hostcheck(char *host) {
    ilist l;

    if (host == NULL)
	return NULL;
    if ((l = deliver_hashmatch(deliver__hnorm,host)) == NULL || l->next != NULL)
	return NULL;

    return l->i;
}

/**
 * initialize the XML delivery system
 *
 * @param p memory pool that can be used to register config handlers (must be available for the livetime of jabberd)
 */
void deliver_init(pool p) {
    deliver__hnorm = xhash_new(401);
    deliver__hlog = xhash_new(401);
    deliver__hxdb = xhash_new(401);
    register_config(p, "host", deliver_config_host, NULL);
    register_config(p, "ns", deliver_config_ns, NULL);
    register_config(p, "logtype", deliver_config_logtype, NULL);
    register_config(p, "uplink", deliver_config_uplink, NULL);
}

/**
 * free the delivery structures ... this is called when we already have shutdown the server
 * therefore we cannot register it with register_shutdown()
 */
void deliver_shutdown(void) {
    if (deliver__hnorm)
	xhash_free(deliver__hnorm);
    if (deliver__hxdb)
	xhash_free(deliver__hxdb);
    if (deliver__hlog)
	xhash_free(deliver__hlog);
    if (deliver__ns)
	xhash_free(deliver__ns);
    if (deliver__logtype)
	xhash_free(deliver__logtype);
}

/**
 * register a function to handle delivery for this instance
 */
void register_phandler(instance id, order o, phandler f, void *arg) {
    handel newh, h1, last;
    pool p;

    /* create handel and setup */
    p = pool_new(); /* use our own little pool */
    newh = static_cast<handel>(pmalloco(p, sizeof(_handel)));
    newh->p = p;
    newh->f = f;
    newh->arg = arg;
    newh->o = o;

    /* if we're the only handler, easy */
    if(id->hds == NULL) {
        id->hds = newh;
        return;
    }

    /* place according to handler preference */
    switch(o) {
	case o_PRECOND:
	    /* always goes to front of list */
	    newh->next = id->hds;
	    id->hds = newh;
	    break;
	case o_COND:
	    h1 = id->hds;
	    last = NULL;
	    while (h1->o < o_PREDELIVER) {
		last = h1;
		h1 = h1->next;
		if (h1 == NULL)
		    break; 
	    }
	    if (last == NULL) {
		/* goes to front of list */
		newh->next = h1;
		id->hds = newh;
	    } else if (h1 == NULL) {
		/* goes at end of list */
		last->next = newh;
	    } else {
		/* goes between last and h1 */
		newh->next = h1;
		last->next = newh;
	    }
	    break;
	case o_PREDELIVER:
	    h1 = id->hds;
	    last = NULL;
	    while (h1->o < o_DELIVER) {
		last = h1;
		h1 = h1->next;
		if (h1 == NULL)
		    break; 
	    }
	    if (last == NULL) {
		/* goes to front of list */
		newh->next = h1;
		id->hds = newh;
	    } else if (h1 == NULL) {
		/* goes at end of list */
		last->next = newh;
	    } else {
		/* goes between last and h1 */
		newh->next = h1;
		last->next = newh;
	    }
	    break;
	case o_DELIVER:
	    /* always add to the end */
	    for (h1 = id->hds; h1->next != NULL; h1 = h1->next)
		/* nothing */;
	    h1->next = newh;
	    break;
	default:
	    ;
    }
}


/**
 * bounce on the delivery, use the result to better gague what went wrong
 */
void deliver_fail(dpacket p, const char *err) {
    xterror xt;
    char message[MAX_LOG_SIZE];

    log_debug2(ZONE, LOGT_DELIVER, "delivery failed (%s)", err);

    if (p==NULL)
	return;

    switch (p->type) {
	case p_LOG:
	    /* stderr and drop */
	    snprintf(message, sizeof(message), "WARNING!  Logging Failed: %s\n", xmlnode_serialize_string(p->x, xmppd::ns_decl_list(), 0));
	    fprintf(stderr, "%s\n", message);
	    pool_free(p->p);
	    break;
	case p_XDB:
	    /* log_warning and drop */
	    log_warn(p->host, "dropping a %s xdb request to %s for %s", xmlnode_get_attrib_ns(p->x,"type", NULL), xmlnode_get_attrib_ns(p->x, "to", NULL), xmlnode_get_attrib_ns(p->x, "ns", NULL));
	    /* drop through and treat like a route failure */
	case p_ROUTE:
	    /* route packet bounce */
	    if (j_strcmp(xmlnode_get_attrib_ns(p->x, "type", NULL),"error") == 0) {
		/* already bounced once, drop */
		log_warn(p->host, "dropping a routed packet to %s from %s: %s", xmlnode_get_attrib_ns(p->x, "to", NULL), xmlnode_get_attrib_ns(p->x, "from", NULL), err);
		pool_free(p->p);
	    } else {
		log_notice(p->host, "bouncing a routed packet to %s from %s: %s", xmlnode_get_attrib_ns(p->x,"to", NULL),xmlnode_get_attrib_ns(p->x, "from", NULL),err);

		/* turn into an error and bounce */
		jutil_tofrom(p->x);
		xmlnode_put_attrib_ns(p->x, "type", NULL, NULL, "error");
		xmlnode_put_attrib_ns(p->x, "error", NULL, NULL, messages_get(xmlnode_get_lang(p->x), err));
		deliver(dpacket_new(p->x),NULL);
	    }
	    break;
	case p_NORM:
	    /* normal packet bounce */
	    if (j_strcmp(xmlnode_get_attrib_ns(p->x, "type", NULL), "error") == 0) {
		/* can't bounce an error */
		log_warn(p->host,"dropping a packet to %s from %s: %s", xmlnode_get_attrib_ns(p->x, "to", NULL), xmlnode_get_attrib_ns(p->x, "from", NULL),err);
		pool_free(p->p);
	    } else {
		log_notice(p->host,"bouncing a packet to %s from %s: %s",xmlnode_get_attrib_ns(p->x, "to", NULL), xmlnode_get_attrib_ns(p->x, "from", NULL),err);

		/* turn into an error */
		if (err == NULL) {
		    jutil_error_xmpp(p->x,XTERROR_EXTERNAL);
		} else {
		    xt = XTERROR_EXTERNAL;
		    strncpy(xt.msg, err, sizeof(xt.msg));
		    xt.msg[sizeof(xt.msg)-1] = 0;
		    jutil_error_xmpp(p->x,xt);
		}
		deliver(dpacket_new(p->x),NULL);
	    }
	    break;
	default:
	    ;
    }
}

/**
 * actually perform the delivery to an instance
 */
void deliver_instance(instance i, dpacket p) {
    handel h, hlast;
    result r;
    dpacket pig = NULL;

    if (i == NULL) {
        deliver_fail(p, N_("Unable to deliver, destination unknown"));
        return;
    }

    log_debug2(ZONE, LOGT_DELIVER, "delivering to instance '%s'", i->id);

    /* try all the handlers */
    hlast = h = i->hds;

    // no handler?
    if (!h) {
	// this may happen if a component does not register_phandler() a handler for packets
	// we either have to bounce or free the packet, else we have a memory leak in this case
	// this may happen with base_dir, if no <out/> is configured.
	deliver_fail(p, N_("Destination has no handler for this stanza."));
	return;
    }

    while (h != NULL) {
        /* there may be multiple delivery handlers, make a backup copy first if we have to */
        if (h->o == o_DELIVER && h->next != NULL)
            pig = dpacket_copy(p);

        /* call the handler */
        if ((r = (h->f)(i,p,h->arg)) == r_ERR) {
            deliver_fail(p, N_("Internal Delivery Error"));
	    return;
        }

        /* if a non-delivery handler says it handled it, we have to be done */
        if (h->o != o_DELIVER && r == r_DONE)
	    return;

	/* a delivery handler says it handled it, and there is no remaining handler, we have to be done as well */
	if (r == r_DONE && h->next == NULL)
	    return;

        /* if a conditional handler wants to halt processing */
        if (h->o == o_COND && r == r_LAST)
	    return;

        /* deal with that backup copy we made */
        if (h->o == o_DELIVER && h->next != NULL) {
            if (r == r_DONE) {
		/* they ate it, use copy */
                p = pig;
		pig = NULL;
	    } else {
                pool_free(pig->p); /* they never used it, trash copy */
	    }
        }

        /* unregister this handler */
        if (r == r_UNREG) {
            if(h == i->hds) {
		/* removing the first in the list */
                i->hds = h->next;
                pool_free(h->p);
                hlast = h = i->hds;
            } else {
		/* removing from anywhere in the list */
                hlast->next = h->next;
                pool_free(h->p);
                h = hlast->next;
            }
            continue;
        }

        hlast = h;
        h = h->next;
    }

    // if we reach here we still have a non-consumed packet we have to free
   pool_free(p->p);
}

/**
 * create a new deliverable packet out of an ::xmlnode
 *
 * @todo shouldn't we check the full localnames and namespaces? (or is it already ensured by the packet type?)
 *
 * @param x the xmlnode to generate the deliverable packet for
 * @return the deliverable packet that has been created
 */
dpacket dpacket_new(xmlnode x) {
    dpacket p;
    char *str;

    if(x == NULL)
        return NULL;

    /* create the new packet */
    p = static_cast<dpacket>(pmalloco(xmlnode_pool(x), sizeof(_dpacket)));
    p->x = x;
    p->p = xmlnode_pool(x);

    /* determine it's type */
    p->type = p_NORM;
    if(*(xmlnode_get_localname(x)) == 'r')	/* XXX check for namespace (check complete name?) */
        p->type = p_ROUTE;
    else if(*(xmlnode_get_localname(x)) == 'x')	/* XXX check for namespace (check complete name?) */
        p->type = p_XDB;
    else if(*(xmlnode_get_localname(x)) == 'l') /* XXX check for namespace (check complete name?) */
        p->type = p_LOG;

    /* xdb results are shipped as normal packets */
    if(p->type == p_XDB && (str = xmlnode_get_attrib_ns(p->x, "type", NULL)) != NULL && (*str == 'r' || *str == 'e' )) /* check full name? */
        p->type = p_NORM;

    /* determine who to route it to, overriding the default to="" attrib only for logs where we use from */
    if(p->type == p_LOG)
        p->id = jid_new(p->p, xmlnode_get_attrib_ns(x, "from", NULL));
    else
        p->id = jid_new(p->p, xmlnode_get_attrib_ns(x, "to", NULL));

    if(p->id == NULL) {
        log_warn(NULL,"Packet Delivery Failed, invalid packet, dropping %s",xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));
        xmlnode_free(x);
        return NULL;
    }

    /* make sure each packet has the basics, norm has a to/from, log has a type, xdb has a namespace */
    switch(p->type) {
	case p_LOG:
	    if (xmlnode_get_attrib_ns(x, "type", NULL) == NULL)
		p=NULL;
	    break;
	case p_XDB:
	    if (xmlnode_get_attrib_ns(x, "ns", NULL) == NULL)
		p=NULL;
	    /* fall through */
	case p_NORM:
	    if (xmlnode_get_attrib_ns(x, "to", NULL) == NULL || xmlnode_get_attrib_ns(x, "from", NULL)==NULL)
		p=NULL;
	    break;
	case p_ROUTE:
	    if (xmlnode_get_attrib_ns(x, "to", NULL) == NULL)
		p=NULL;
	    break;
	case p_NONE:
	    p=NULL;
	    break;
    }
    if (p==NULL) {
        log_warn(NULL, "Packet Delivery Failed, invalid packet, dropping %s",xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));
        xmlnode_free(x);
        return NULL;
    }

    p->host = p->id->server;
    return p;
}

/**
 * create a clone of a deliverable packet
 */
dpacket dpacket_copy(dpacket p) {
    dpacket p2;

    p2 = dpacket_new(xmlnode_dup(p->x));
    return p2;
}

/**
 * register a function that gets called on registering/unregistering a host for an instance
 */
void register_routing_update_callback(instance i, register_notify f, void *arg) {
    register_notifier last = NULL;
    register_notifier newn = NULL;

    log_debug2(ZONE, LOGT_EXECFLOW, "register_routing_update_callback(%x, %x, %x)", i, f, arg);

    /* sanity check */
    if (i==NULL || f == NULL)
	return;

    /* search end of list of already registered callback */
    for (last = i->routing_update_callbacks; last != NULL && last->next != NULL; last = last->next)
	; /* nothing */

    /* create new list element */
    newn = static_cast<register_notifier>(pmalloco(i->p, sizeof(_register_notifier)));
    newn->callback = f;
    newn->arg = arg;

    /* append to list */
    if (last == NULL)
	i->routing_update_callbacks = newn;
    else
	last->next = newn;
}

#ifdef POOL_DEBUG
class instance_statistics {
    private:
	int count;
	size_t pool_sum;
	size_t biggest_pool;
	std::string biggest_pool_name;

    public:
	instance_statistics();
	void update(instance i);
	std::string getSummary();
};

instance_statistics::instance_statistics() : count(0), pool_sum(0), biggest_pool(0) {
};

void instance_statistics::update(instance i) {
    size_t this_instances_size = pool_size(i->p);
    
    count++;
    pool_sum += this_instances_size;

    if (this_instances_size > biggest_pool) {
	biggest_pool = this_instances_size;
	biggest_pool_name = i->id;
    }
}

std::string instance_statistics::getSummary() {
    std::ostringstream result;

    result << "Instances: " << count << " / Mem in pools: " << pool_sum << " / biggest: " << biggest_pool << " " << biggest_pool_name;

    return result.str();
}

static void _deliver_instance_stat_walker(xht hash, const char* key, void* value, void* arg) {
    instance_statistics* stats = static_cast<instance_statistics*>(arg);
    ilist il = static_cast<ilist>(value);

    // sanity check
    if (stats == NULL || il == NULL) {
	return;
    }

    while (il != NULL) {
	stats->update(il->i);
	il = il->next;
    }
}

void deliver_pool_debug() {
    instance_statistics* stats = new instance_statistics;

    xhash_walk(deliver_hashtable(p_LOG), _deliver_instance_stat_walker, stats);
    xhash_walk(deliver_hashtable(p_XDB), _deliver_instance_stat_walker, stats);
    xhash_walk(deliver_hashtable(p_NORM), _deliver_instance_stat_walker, stats);

    static char own_pid[32] = "";
    if (own_pid[0] == '\0') {
	snprintf(own_pid, sizeof(own_pid), "%i deliver_pool_debug", getpid());
    }

    log_notice(own_pid, "%s", stats->getSummary().c_str());

    delete stats;
}
#else
void deliver_pool_debug() {
}
#endif
