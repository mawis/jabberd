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
#include <dlfcn.h>
#include "jabberd.h"

xmlnode base_load__cache = NULL;
int base_load_ref__count = 0;

/* process entire load element, loading each one (unless already cached) */
/* if all loaded, exec each one in order */

/* they register a handler to accept incoming xmlnodes that get delivered to them */
/* base_load sends packets on when it receives them */

void *base_load_loader(char *file)
{
    void *so_h;
    char *dlerr;
    char message[MAX_LOG_SIZE];

    /* load the dso */
    so_h = dlopen(file,RTLD_LAZY);

    /* check for a load error */
    dlerr = dlerror();
    if(dlerr != NULL)
    {
        snprintf(message, MAX_LOG_SIZE, "Loading %s failed: '%s'\n",file,dlerr);
        fprintf(stderr, "%s\n", message);
        return NULL;
    }

    xmlnode_put_vattrib(base_load__cache, file, so_h); /* fun hack! yes, it's just a nice name-based void* array :) */
    return so_h;
}

void *base_load_symbol(char *func, char *file)
{
    void (*func_h)(instance i, void *arg);
    void *so_h;
    char *dlerr;
    char message[MAX_LOG_SIZE];

    if(func == NULL || file == NULL)
        return NULL;

    if((so_h = xmlnode_get_vattrib(base_load__cache, file)) == NULL && (so_h = base_load_loader(file)) == NULL)
        return NULL;

    /* resolve a reference to the dso's init function */
    func_h = dlsym(so_h, func);

    /* check for error */
    dlerr = dlerror();
    if(dlerr != NULL)
    {
        snprintf(message, MAX_LOG_SIZE, "Executing %s() in %s failed: '%s'\n",func,file,dlerr);
        fprintf(stderr, "%s\n", message);
        return NULL;
    }

    return func_h;
}

void base_load_shutdown(void *arg)
{
    base_load_ref__count--;
    if(base_load_ref__count != 0)
        return;

    xmlnode_free(base_load__cache);
    base_load__cache = NULL;
}

result base_load_config(instance id, xmlnode x, void *arg)
{
    xmlnode so;
    char *init = xmlnode_get_attrib(x,"main");
    void *f;
    int flag = 0;

    if(base_load__cache == NULL)
        base_load__cache = xmlnode_new_tag("so_cache");

    if(id != NULL)
    { /* execution phase */
        base_load_ref__count++;
        pool_cleanup(id->p, base_load_shutdown, NULL);
        f = xmlnode_get_vattrib(x, init);
        ((base_load_init)f)(id, x); /* fire up the main function for this extension */
        return r_PASS;
    }

    
    log_debug(ZONE,"base_load_config processing configuration %s\n",xmlnode2str(x));

    for(so = xmlnode_get_firstchild(x); so != NULL; so = xmlnode_get_nextsibling(so))
    {
        if(xmlnode_get_type(so) != NTYPE_TAG) continue;

        if(init == NULL && flag)
            return r_ERR; /* you can't have two elements in a load w/o a main attrib */

        f = base_load_symbol(xmlnode_get_name(so), xmlnode_get_data(so));
        if(f == NULL)
            return r_ERR;
        xmlnode_put_vattrib(x, xmlnode_get_name(so), f); /* hide the function pointer in the <load> element for later use */
        flag = 1;

        /* if there's only one .so loaded, it's the default, unless overridden */
        if(init == NULL)
            xmlnode_put_attrib(x,"main",xmlnode_get_name(so));
    }

    if(!flag) return r_ERR; /* we didn't DO anything, duh */

    return r_PASS;
}


void base_load(void)
{
    log_debug(ZONE,"base_load loading...\n");
    register_config("load",base_load_config,NULL);
}



/************ BELOW IS UTILITY SYMBOLS FOR LOADED MODULES ***************/

/* CREATE an xdb blocked ring
each entry has a new int and is placed as the id="int" value
incoming results are intercepted and that entry is unblocked
some sort of timer that scans the ring oldest to newest, resending stale requests
timeout xdb requests after a while, unblock and newx.data is still NULL
start sending logs depending on length of staleness
*/

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

/*** mtq is Managed Thread Queues ***/
/* they queue calls to be run sequentially on a thread, that comes from a system pool of threads */

typedef struct mtqcall_struct
{
    pth_message_t head; /* the standard pth message header */
    mtq_callback f; /* function to run within the thread */
    void *arg; /* the data for this call */
    mtq q; /* if this is a queue to process */
} _mtqcall, *mtqcall;

typedef struct mtqmaster_struct
{
    mth all[MTQ_THREADS];
    int overflow;
    pth_msgport_t mp;
} *mtqmaster, _mtqmaster;

mtqmaster mtq__master = NULL;

/* cleanup a queue when it get's free'd */
void mtq_cleanup(void *arg)
{
    mtq q = (mtq)arg;
    mtqcall c;

    /* if there's a thread using us, make sure we disassociate ourselves with them */
    if(q->t != NULL)
        q->t->q = NULL;

    /* What?  not empty?!?!?! probably a programming/sequencing error! */
    while((c = (mtqcall)pth_msgport_get(q->mp)) != NULL)
    {
        log_debug("mtq","%X last call %X",q->mp,c->arg);
        (*(c->f))(c->arg);
    }
    pth_msgport_destroy(q->mp);
}

/* public queue creation function, queue lives as long as the pool */
mtq mtq_new(pool p)
{
    mtq q;

    if(p == NULL) return NULL;

    log_debug(ZONE,"MTQ(new)");

    /* create queue */
    q = pmalloco(p, sizeof(_mtq));

    /* create msgport */
    q->mp = pth_msgport_create("mtq");

    /* register cleanup handler */
    pool_cleanup(p, mtq_cleanup, (void *)q);

    return q;
}

/* main slave thread */
void *mtq_main(void *arg)
{
    mth t = (mth)arg;
    pth_event_t mpevt;
    mtqcall c;

    log_debug("mtq","%X starting",t->id);

    /* create an event ring for receiving messges */
    mpevt = pth_event(PTH_EVENT_MSG,t->mp);

    /* loop */
    while(1)
    {

        /* before checking our mp, see if the master one has overflow traffic in it */
        if(mtq__master->overflow)
        {
            /* get the call from the master */
            c = (mtqcall)pth_msgport_get(mtq__master->mp);
            if(c == NULL)
            { /* empty! */
                mtq__master->overflow = 0;
                continue;
            }
        }else{
            /* debug: note that we're waiting for a message */
            log_debug("mtq","%X leaving to pth",t->id);
            t->busy = 0;

            /* wait for a master message on the port */
            pth_wait(mpevt);

            /* debug: note that we're working */
            log_debug("mtq","%X entering from pth",t->id);
            t->busy = 1;

            /* get the message */
            c = (mtqcall)pth_msgport_get(t->mp);
            if(c == NULL) continue;
        }


        /* check for a simple "one-off" call */
        if(c->q == NULL)
        {
            log_debug("mtq","%X one call %X",t->id,c->arg);
            (*(c->f))(c->arg);
            continue;
        }

        /* we've got a queue call, associate ourselves and process all it's packets */
        t->q = c->q;
        t->q->t = t;
        while((c = (mtqcall)pth_msgport_get(t->q->mp)) != NULL)
        {
            log_debug("mtq","%X queue call %X",t->id,c->arg);
            (*(c->f))(c->arg);
            if(t->q == NULL) break;
        }

        /* disassociate the thread and queue since we processed all the packets */
        /* XXX future pthreads note: mtq_send() could have put another call on the queue since we exited the while, that would be bad */
        if(t->q != NULL)
        {
            t->q->t = NULL; /* make sure the queue doesn't point to us anymore */
            t->q->routed = 0; /* nobody is working on the queue anymore */
            t->q = NULL; /* we're not working on the queue */
        }

    }

    /* free all memory stuff associated with the thread */
    pth_event_free(mpevt,PTH_FREE_ALL);
    pth_msgport_destroy(t->mp);
    pool_free(t->p);
    return NULL;
}

void mtq_send(mtq q, pool p, mtq_callback f, void *arg)
{
    mtqcall c;
    mth t = NULL;
    int n;
    pool newp;
    pth_msgport_t mp = NULL; /* who to send the call too */
    pth_attr_t attr;

    /* initialization stuff */
    if(mtq__master == NULL)
    {
        mtq__master = malloc(sizeof(_mtqmaster)); /* happens once, global */
        mtq__master->mp = pth_msgport_create("mtq__master");
        for(n=0;n<MTQ_THREADS;n++)
        {
            newp = pool_new();
            t = pmalloco(newp, sizeof(_mth));
            t->p = newp;
            t->mp = pth_msgport_create("mth");
            attr = pth_attr_new();
            pth_attr_set(attr, PTH_ATTR_PRIO, PTH_PRIO_MAX);
            t->id = pth_spawn(attr, mtq_main, (void *)t);
            pth_attr_destroy(attr);
            mtq__master->all[n] = t; /* assign it as available */
        }
    }

    /* find a waiting thread */
    for(n = 0; n < MTQ_THREADS; n++)
        if(mtq__master->all[n]->busy == 0)
        {
            mp = mtq__master->all[n]->mp;
            mtq__master->all[n]->busy = 1;
            break;
        }

    /* if there's no thread available, dump in the overflow msgport */
    if(mp == NULL)
    {
        log_debug("mtqoverflow","%d overflowing %X",mtq__master->overflow,arg);
        mp = mtq__master->mp;
        mtq__master->overflow++;
    }

    /* track this call */
    c = pmalloco(p, sizeof(_mtqcall));
    c->f = f;
    c->arg = arg;

    /* if we don't have a queue, just send it */
    if(q == NULL)
    {
        pth_msgport_put(mp, (pth_message_t *)c);
        return;
    }

    /* if we have a queue, insert it there */
    pth_msgport_put(q->mp, (pth_message_t *)c);

    /*if(pth_msgport_pending(q->mp) > 10)
        log_debug("mtqoverflow","%d queue overflow on %X",pth_msgport_pending(q->mp),q->mp);*/

    /* if we haven't told anyone to take this queue yet */
    if(q->routed == 0)
    {
        c = pmalloco(p, sizeof(_mtqcall));
        c->q = q;
        pth_msgport_put(mp, (pth_message_t *)c);
        q->routed = 1;
    }
}

