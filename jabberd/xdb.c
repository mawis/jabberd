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

result xdb_results(instance id, dpacket p, void *arg)
{
    xdbcache xc = (xdbcache)arg;
    xdbcache curx;
    int idnum;
    char *idstr;

    if(p->type != p_NORM || *(xmlnode_get_name(p->x)) != 'x') return r_PASS;

    log_debug(ZONE,"xdb_results checking xdb packet %s",xmlnode2str(p->x));

    if((idstr = xmlnode_get_attrib(p->x,"id")) == NULL) return r_ERR;

    idnum = atoi(idstr);

    for(curx = xc->next; curx->id != idnum && curx != xc; curx = curx->next); /* spin till we are where we started or find our id# */

    /* we got an id we didn't have cached, could be a dup, ignore and move on */
    if(curx->id != idnum)
    {
        pool_free(p->p);
        return r_DONE;
    }

    /* associte packet w/ waiting cache */
    curx->data = p->x;

    /* remove from ring */
    curx->prev->next = curx->next;
    curx->next->prev = curx->prev;

    /* free the thread! */
    curx->preblock = 0;
    if(curx->cond != NULL)
        pth_cond_notify(curx->cond, FALSE);

    return r_DONE; /* we processed it */
}

/* actually deliver the xdb request */
void xdb_deliver(instance i, xdbcache xc)
{
    xmlnode x;
    jid dude;
    char ids[9];

    x = xmlnode_new_tag("xdb");
    dude = jid_new(xmlnode_pool(x),jid_full(xc->owner));
    jid_set(dude,xc->ns,JID_RESOURCE);
    if(xc->data == NULL)
    {
        xmlnode_put_attrib(x,"type","get");
    }else{
        xmlnode_put_attrib(x,"type","set");
        xmlnode_insert_tag_node(x,xc->data); /* copy in the data */
    }
    xmlnode_put_attrib(x,"to",jid_full(dude));
    xmlnode_put_attrib(x,"from",xc->host);
    sprintf(ids,"%d",xc->id);
    xmlnode_put_attrib(x,"id",ids); /* to track response */
    deliver(dpacket_new(x), i);
}

result xdb_thump(void *arg)
{
    xdbcache xc = (xdbcache)arg;
    xdbcache cur, next;
    int now = time(NULL);

    /* spin through the cache looking for stale requests */
    cur = xc->next;
    while(cur != xc)
    {
        next = cur->next;

        /* really old ones get wacked */
        if((now - cur->sent) > 30)
        {
            /* remove from ring */
            cur->prev->next = cur->next;
            cur->next->prev = cur->prev;

            /* make sure it's null as a flag for xdb_set's */
            cur->data = NULL;

            /* free the thread! */
            cur->preblock = 0;
            if(cur->cond != NULL)
                pth_cond_notify(cur->cond, FALSE);

            cur = next;
            continue;
        }

        /* resend the waiting ones every so often */
        if((now - cur->sent) > 10)
            xdb_deliver(xc->i, cur);

        /* cur could have been free'd already on it's thread */
        cur = next;
    }

    return r_DONE;
}

xdbcache xdb_cache(instance id)
{
    xdbcache newx;

    if(id == NULL)
    {
        fprintf(stderr, "Programming Error: xdb_cache() called with NULL\n");
        return NULL;
    }

    newx = pmalloco(id->p, sizeof(_xdbcache));
    newx->i = id; /* flags it as the top of the ring too */
    newx->next = newx->prev = newx; /* init ring */

    /* register the handler in the instance to filter out xdb results */
    register_phandler(id, o_PRECOND, xdb_results, (void *)newx);

    /* heartbeat to keep a watchful eye on xdb_cache */
    register_beat(10,xdb_thump,(void *)newx);

    return newx;
}

/* blocks until namespace is retrieved, host must map back to this service! */
xmlnode xdb_get(xdbcache xc, char *host, jid owner, char *ns)
{
    _xdbcache newx;
    xmlnode x;
    pth_mutex_t mutex = PTH_MUTEX_INIT;
    pth_cond_t cond = PTH_COND_INIT;

    if(xc == NULL || owner == NULL || ns == NULL)
    {
        fprintf(stderr,"Programming Error: xdb_get() called with NULL\n");
        return NULL;
    }

    /* init this newx */
    newx.i = NULL;
    newx.data = NULL;
    newx.host = host;
    newx.ns = ns;
    newx.owner = owner;
    newx.sent = time(NULL);
    newx.preblock = 1; /* flag */
    newx.cond = NULL;

    /* in the future w/ real threads, would need to lock xc to make these changes to the ring */
    newx.id = xc->id++;
    newx.next = xc->next;
    newx.prev = xc;
    newx.next->prev = &newx;
    xc->next = &newx;

    /* send it on it's way */
    xdb_deliver(xc->i, &newx);

    /* if it hasn't already returned, we should block here until it returns */
    if(newx.preblock)
    {
        log_debug(ZONE,"xdb_get() waiting for %s %s",jid_full(owner),ns);
        newx.cond = &cond;
        pth_mutex_acquire(&mutex, FALSE, NULL);
        pth_cond_await(&cond, &mutex, NULL); /* blocks thread */
        log_debug(ZONE,"xdb_get() done waiting for %s %s",jid_full(owner),ns);
    }

    /* newx.data is now the returned xml packet */

    /* return the xmlnode inside <xdb>...</xdb> */
    for(x = xmlnode_get_firstchild(newx.data); x != NULL && xmlnode_get_type(x) != NTYPE_TAG; x = xmlnode_get_nextsibling(x));

    /* there were no children (results) to the xdb request, free the packet */
    if(x == NULL)
        xmlnode_free(newx.data);

    return x;
}

/* sends new xml to replace old, data is NOT freed, app responsible for freeing it */
int xdb_set(xdbcache xc, char *host, jid owner, char *ns, xmlnode data)
{
    _xdbcache newx;
    pth_mutex_t mutex = PTH_MUTEX_INIT;
    pth_cond_t cond = PTH_COND_INIT;

    if(xc == NULL || host == NULL || owner == NULL || ns == NULL || data == NULL)
    {
        fprintf(stderr,"Programming Error: xdb_set() called with NULL\n");
        return 1;
    }

    /* init this newx */
    newx.i = NULL;
    newx.data = data;
    newx.host = host;
    newx.ns = ns;
    newx.owner = owner;
    newx.sent = time(NULL);
    newx.preblock = 1; /* flag */
    newx.cond = NULL;

    /* in the future w/ real threads, would need to lock xc to make these changes to the ring */
    newx.id = xc->id++;
    newx.next = xc->next;
    newx.prev = xc;
    newx.next->prev = &newx;
    xc->next = &newx;

    /* send it on it's way */
    xdb_deliver(xc->i, &newx);

    /* if it hasn't already returned, we should block here until it returns */
    if(newx.preblock)
    {
        log_debug(ZONE,"xdb_set() waiting for %s %s",jid_full(owner),ns);
        newx.cond = &cond;
        pth_mutex_acquire(&mutex, FALSE, NULL);
        pth_cond_await(&cond, &mutex, NULL); /* blocks thread */
        log_debug(ZONE,"xdb_set() done waiting for %s %s",jid_full(owner),ns);
    }

    /* newx.data is now the returned xml packet or NULL if it was unsuccessful */

    /* if it didn't actually get set, flag that */
    if(newx.data == NULL)
        return 1;

    xmlnode_free(newx.data);
    return 0;
}

