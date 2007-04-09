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
 * @file xdb.cc
 * @brief implement the interface to the XML database access
 */

#include "jabberd.h"

/**
 * ::o_PRECOND packet handler that filters the packets incoming for the instance to look for xdb packets
 *
 * @param id the ::instance this packet gets delivered to
 * @param p the ::dpacket that gets delivered
 * @param arg the ::xdbcache incoming xdb results would be for
 * @return r_PASS if we don't care about this packet, r_DONE if it has been an xdb packet we could handle, r_ERR if it was an invalid xdb packet
 */
static result xdb_results(instance id, dpacket p, void *arg) {
    xdbcache xc = (xdbcache)arg;
    xdbcache curx;
    int idnum;
    char *idstr;

    if(p->type != p_NORM || *(xmlnode_get_localname(p->x)) != 'x' || j_strcmp(xmlnode_get_namespace(p->x), NS_SERVER) != 0)
	return r_PASS; /* yes, we are matching ANY <x*> element */

    log_debug2(ZONE, LOGT_STORAGE, "xdb_results checking xdb packet %s",xmlnode_serialize_string(p->x, xmppd::ns_decl_list(), 0));

    // we need an id on the xdb as this is what we use to find the query this result is for
    if((idstr = xmlnode_get_attrib_ns(p->x, "id", NULL)) == NULL)
	return r_ERR;

    idnum = atoi(idstr);

    pth_mutex_acquire(&(xc->mutex), FALSE, NULL);
    for(curx = xc->next; curx->id != idnum && curx != xc; curx = curx->next); /* spin till we are where we started or find our id# */

    /* we got an id we didn't have cached, could be a dup, ignore and move on */
    if(curx->id != idnum)
    {
        pool_free(p->p);
        pth_mutex_release(&(xc->mutex));
        return r_DONE;
    }

    /* associte only a non-error packet w/ waiting cache */
    if(j_strcmp(xmlnode_get_attrib_ns(p->x, "type", NULL),"error") == 0)
        curx->data = NULL;
    else
        curx->data = p->x;

    /* remove from ring */
    curx->prev->next = curx->next;
    curx->next->prev = curx->prev;


    /* set the flag to not block, and signal */
    curx->preblock = 0;
    pth_cond_notify(&(curx->cond), FALSE);

    /* Now release the master xc mutex */
    pth_mutex_release(&(xc->mutex));

    return r_DONE; /* we processed it */
}

/**
 * actually deliver the xdb request
 *
 * Should be called while holding the xc mutex
 *
 * The xdb stanza gets created and delivered
 *
 * @param i the instance this xdb request is sent by
 * @param xc the ::_xdbcache instance that holds the request (not the head of the xdbcache)
 */
static void xdb_deliver(instance i, xdbcache xc) {
    xmlnode x;
    char ids[9];

    x = xmlnode_new_tag_ns("xdb", NULL, NS_SERVER);
    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "get");
    if (xc->set) {
        xmlnode_put_attrib_ns(x, "type", NULL, NULL, "set");
        xmlnode_insert_tag_node(x,xc->data); /* copy in the data */
        if (xc->act != NULL)
            xmlnode_put_attrib_ns(x, "action", NULL, NULL, xc->act);
        if (xc->match != NULL)
            xmlnode_put_attrib_ns(x, "match", NULL, NULL, xc->match);
	if (xc->matchpath != NULL)
	    xmlnode_put_attrib_ns(x, "matchpath", NULL, NULL, xc->matchpath);
	if (xc->namespaces != NULL) {
	    xmlnode namespaces = xhash_to_xml(xc->namespaces);
	    xmlnode_put_attrib_ns(x, "matchns", NULL, NULL, xmlnode_serialize_string(namespaces, xmppd::ns_decl_list(), 0));
	    xmlnode_free(namespaces);
	}
    }
    xmlnode_put_attrib_ns(x, "to", NULL, NULL, jid_full(xc->owner));
    xmlnode_put_attrib_ns(x, "from", NULL, NULL, i->id);
    xmlnode_put_attrib_ns(x, "ns", NULL, NULL, xc->ns);
    snprintf(ids, sizeof(ids), "%d", xc->id);
    xmlnode_put_attrib_ns(x, "id", NULL, NULL, ids); /* to track response */
    log_debug2(ZONE, LOGT_EXECFLOW, "delivering xdb request: %s", xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));
    deliver(dpacket_new(x), i);
}

/**
 * beat handler for an xdbcache
 *
 * resends unresponded xdb queries after 10 seconds and removes unresponded xdb queries after 30 seconds.
 *
 * @param arg the xdbcache this function is called for
 * @return always r_DONE
 */
static result xdb_thump(void *arg) {
    xdbcache xc = (xdbcache)arg;
    xdbcache cur, next;
    int now = time(NULL);

    pth_mutex_acquire(&(xc->mutex), FALSE, NULL);
    /* spin through the cache looking for stale requests */
    cur = xc->next;
    while (cur != xc) {
        next = cur->next;

        /* really old ones get wacked */
        if ((now - cur->sent) > 30) {
            /* remove from ring */
            cur->prev->next = cur->next;
            cur->next->prev = cur->prev;

            /* make sure it's null as a flag for xdb_set's */
            cur->data = NULL;

            /* free the thread! */
            if (cur->preblock) {
                cur->preblock = 0;
                pth_cond_notify(&(cur->cond), FALSE);
            }

            cur = next;
            continue;
        }

        /* resend the waiting ones every so often */
        if ((now - cur->sent) > 10)
            xdb_deliver(xc->i, cur);

        /* cur could have been free'd already on it's thread */
        cur = next;
    }

    pth_mutex_release(&(xc->mutex));
    return r_DONE;
}

/**
 * create an xdbcache for the specified instance
 *
 * This creates the ::_xdbcache structure from the memory pool of the instance, and registers two handlers:
 * One handler is registered to get/handle the xdb responses that are delivered to the instance. The other
 * handler is registered to get called regularily every 10 seconds.
 *
 * @param id the ::instance to create the ::_xdbcache for.
 * @return the newly created xdbcache
 */
xdbcache xdb_cache(instance id) {
    xdbcache newx;

    // sanity check
    if (id == NULL) {
        fprintf(stderr, "Programming Error: xdb_cache() called with NULL\n");
        return NULL;
    }

    // allocate the structure and init it
    newx = static_cast<xdbcache>(pmalloco(id->p, sizeof(_xdbcache)));
    newx->i = id; /* flags it as the top of the ring too */
    newx->next = newx->prev = newx; /* init ring */
    pth_mutex_init(&(newx->mutex)); // init mutex that protects the access to the xdbcache

    /* register the handler in the instance to filter out xdb results */
    register_phandler(id, o_PRECOND, xdb_results, (void *)newx);

    /* heartbeat to keep a watchful eye on xdb_cache */
    register_beat(10,xdb_thump,(void *)newx);

    return newx;
}

/**
 * query data from the xdb
 *
 * blocks until namespace is retrieved, host must map back to this service!
 *
 * @param xc the xdbcache used for this query
 * @param owner for which JID the query should be made
 * @param ns which namespace to query
 * @return NULL if nothing found, result else (has to be freed by the caller!)
 */
xmlnode xdb_get(xdbcache xc, jid owner, const char *ns) {
    _xdbcache newx;
    xmlnode x;
    /* pth_cond_t cond = PTH_COND_INIT; */

    if (xc == NULL || owner == NULL || ns == NULL) {
        fprintf(stderr, "Programming Error: xdb_get() called with NULL\n");
        return NULL;
    }

    /* init this newx */
    newx.i = NULL;
    newx.set = 0;
    newx.data = NULL;
    newx.ns = ns;
    newx.owner = owner;
    newx.sent = time(NULL);
    newx.preblock = 1; /* flag */
    pth_cond_init(&(newx.cond));

    /* in the future w/ real threads, would need to lock xc to make these changes to the ring */
    pth_mutex_acquire(&(xc->mutex), FALSE, NULL);
    newx.id = xc->id++;
    newx.next = xc->next;
    newx.prev = xc;
    newx.next->prev = &newx;
    xc->next = &newx;

    /* send it on it's way, holding the lock */
    xdb_deliver(xc->i, &newx);

    log_debug2(ZONE, LOGT_STORAGE|LOGT_THREAD, "xdb_get() waiting for %s %s",jid_full(owner),ns);
    if (newx.preblock)
        pth_cond_await(&(newx.cond), &(xc->mutex), NULL); /* blocks thread */
    pth_mutex_release(&(xc->mutex));

    /* we got signalled */
    log_debug2(ZONE, LOGT_STORAGE|LOGT_THREAD, "xdb_get() done waiting for %s %s",jid_full(owner),ns);

    /* newx.data is now the returned xml packet */
    /* return the xmlnode inside <xdb>...</xdb> */
    for(x = xmlnode_get_firstchild(newx.data); x != NULL && xmlnode_get_type(x) != NTYPE_TAG; x = xmlnode_get_nextsibling(x));

    /* there were no children (results) to the xdb request, free the packet */
    if(x == NULL)
        xmlnode_free(newx.data);

    return x;
}

/* sends new xml xdb action, data is NOT freed, app responsible for freeing it */
/* act must be NULL, "check", or "insert" for now, insert will either blindly insert data into the parent (creating one if needed) or use match */
/* match will find a child in the parent, and either replace (if it's an insert) or remove (if data is NULL) */
/* XXX for the check action, read the comment in xdb_file/xdb_file.c, it might be buggy and not needed anyway */
static int _xdb_act(xdbcache xc, jid owner, const char *ns, char *act, char *match, char *matchpath, xht namespaces, xmlnode data) {
    _xdbcache newx;

    if (xc == NULL || owner == NULL || ns == NULL) {
        fprintf(stderr,"Programming Error: xdb_set() called with NULL\n");
        return 1;
    }

    /* init this newx */
    newx.i = NULL;
    newx.set = 1;
    newx.data = data;
    newx.ns = ns;
    newx.act = act;
    newx.match = match;
    newx.matchpath = matchpath;
    newx.namespaces = namespaces;
    newx.owner = owner;
    newx.sent = time(NULL);
    newx.preblock = 1; /* flag */
    pth_cond_init(&(newx.cond));

    /* in the future w/ real threads, would need to lock xc to make these changes to the ring */
    pth_mutex_acquire(&(xc->mutex), FALSE, NULL);
    newx.id = xc->id++;
    newx.next = xc->next;
    newx.prev = xc;
    newx.next->prev = &newx;
    xc->next = &newx;

    /* send it on it's way */
    xdb_deliver(xc->i, &newx);

    /* wait for the condition var */
    log_debug2(ZONE, LOGT_STORAGE|LOGT_THREAD, "xdb_set() waiting for %s %s",jid_full(owner),ns);
    /* preblock is set to 0 if it beats us back here */
    if (newx.preblock)
        pth_cond_await(&(newx.cond), &(xc->mutex), NULL); /* blocks thread */
    pth_mutex_release(&(xc->mutex));

    /* we got signalled */
    log_debug2(ZONE, LOGT_STORAGE|LOGT_THREAD, "xdb_set() done waiting for %s %s",jid_full(owner),ns);

    /* newx.data is now the returned xml packet or NULL if it was unsuccessful */
    /* if it didn't actually get set, flag that */
    if(newx.data == NULL)
        return 1;

    xmlnode_free(newx.data);
    return 0;
}

int xdb_act(xdbcache xc, jid owner, const char *ns, char *act, char *match, xmlnode data) {
    return _xdb_act(xc, owner, ns, act, match, NULL, NULL, data);
}

int xdb_act_path(xdbcache xc, jid owner, const char *ns, char *act, char *matchpath, xht namespaces, xmlnode data) {
    return _xdb_act(xc, owner, ns, act, NULL, matchpath, namespaces, data);
}

/* sends new xml to replace old, data is NOT freed, app responsible for freeing it */
int xdb_set(xdbcache xc, jid owner, const char *ns, xmlnode data) {
    return _xdb_act(xc, owner, ns, NULL, NULL, NULL, NULL, data);
}
