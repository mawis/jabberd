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

/* <jer mode="pondering">

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
int deliver__flag=0;
pth_msgport_t deliver__mp=NULL;
typedef struct deliver_mp_st
{
    pth_message_t head;
    instance i;
    dpacket p;
} _deliver_msg,*deliver_msg;

typedef struct ilist_struct
{
    instance i;
    struct ilist_struct *next;
} *ilist, _ilist;

ilist ilist_add(ilist il, instance i)
{
    ilist ilnew;

    ilnew = pmalloco(i->p, sizeof(_ilist));
    ilnew->i = i;
    ilnew->next = il;
    return ilnew;
}

ilist ilist_rem(ilist il, instance i)
{
    ilist cur;

    if(il == NULL) return NULL;

    if(il->i == i) return il->next;

    for(cur = il; cur->next != NULL; cur = cur->next)
        if(cur->next->i == i)
        {
            cur->next = cur->next->next;
            return il;
        }

    return NULL;
}

/* XXX handle removing things from the list too, yuck */

/* set up our global delivery logic tracking vars */

HASHTABLE deliver__hnorm = NULL; /* hosts for normal packets, important and most frequently used one */
HASHTABLE deliver__hxdb = NULL; /* host filters for xdb requests */
HASHTABLE deliver__hlog = NULL; /* host filters for logging */
HASHTABLE deliver__ns = NULL; /* namespace filters for xdb */
HASHTABLE deliver__logtype = NULL; /* log types, fixed set, but it's easier (wussier) to just be consistent and use a hashtable */

ilist deliver__all = NULL; /* all instances */
instance deliver__uplink = NULL; /* uplink instance, only one */

/* utility to find the right hashtable based on type */
HASHTABLE deliver_hashtable(ptype type)
{
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

/* utility to find the right ilist in the hashtable */
ilist deliver_hashmatch(HASHTABLE ht, char *key)
{
    ilist l;
    l = ghash_get(ht, key);
    if(l == NULL)
        l = ghash_get(ht, "*");
    return l;
}

/* find and return the instance intersecting both lists, or react intelligently */
instance deliver_intersect(ilist a, ilist b)
{
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

void deliver_xdb(dpacket p)
{
    ilist a, b;

    b = NULL;
    a = deliver_hashmatch(deliver_hashtable(p->type), p->host);
    if(p->type == p_XDB)
        b = deliver_hashmatch(deliver__ns, p->id->resource); /* XXX xdb ns/folder support? */
    else if(p->type == p_LOG)
        b = deliver_hashmatch(deliver__ns, xmlnode_get_attrib(p->x,"type"));

    deliver_instance(deliver_intersect(a, b), p);
}


result deliver_config_host(instance i, xmlnode x, void *arg)
{
    ilist l;
    HASHTABLE ht;
    char *host, star[] = "*";

    if(i == NULL)
        return r_PASS;

    /* do some validation checks here */

    /* fail, since ns is required on every XDB instance if it's used on any one */
    if(i->type == p_XDB && deliver__ns != NULL && xmlnode_get_tag(i->x, "ns") == NULL) return r_ERR;
    /* fail, since logtype is required on every LOG instance if it's used on any one */
    if(i->type == p_LOG && deliver__logtype != NULL && xmlnode_get_tag(i->x, "logtype") == NULL) return r_ERR;

    host = xmlnode_get_data(x);
    if(host == NULL)
        host = star;

    ht = deliver_hashtable(i->type);
    l = ghash_get(ht, host);
    l = ilist_add(l, i);
    ghash_put(ht, host, (void *)l);

    return r_DONE;
}

result deliver_config_ns(instance i, xmlnode x, void *arg)
{
    ilist l;
    char *ns, star[] = "*";

    if(i == NULL)
        return r_PASS;

    if(i->type != p_XDB)
        return r_ERR;

    ns = xmlnode_get_data(x);
    if(ns == NULL)
        ns = star;

    l = ghash_get(deliver__ns, ns);
    l = ilist_add(l, i);
    ghash_put(deliver__ns, ns, (void *)l);

    return r_DONE;
}

result deliver_config_logtype(instance i, xmlnode x, void *arg)
{
    ilist l;
    char *type, star[] = "*";

    if(i == NULL)
        return r_PASS;

    if(i->type != p_LOG)
        return r_ERR;

    type = xmlnode_get_data(x);
    if(type == NULL)
        type = star;

    l = ghash_get(deliver__logtype, type);
    l = ilist_add(l, i);
    ghash_put(deliver__logtype, type, (void *)l);

    return r_DONE;
}

void deliver_init(void)
{
    deliver__hnorm = ghash_create(401,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
    deliver__hlog = ghash_create(401,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
    deliver__hxdb = ghash_create(401,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
    register_config("host",deliver_config_host,NULL);
    register_config("ns",deliver_config_ns,NULL);
    register_config("logtype",deliver_config_logtype,NULL);
}

/* register a function to handle delivery for this instance */
void register_phandler(instance id, order o, phandler f, void *arg)
{
    handel newh, h1, last;
    pool p;

    /* create handel and setup */
    p = pool_new(); /* use our own little pool */
    newh = pmalloc_x(p, sizeof(_handel), 0);
    newh->p = p;
    newh->f = f;
    newh->arg = arg;
    newh->o = o;

    /* if we're the only handler, easy */
    if(id->hds == NULL)
    {
        id->hds = newh;
        return;
    }

    /* place according to handler preference */
    switch(o)
    {
    case o_PRECOND:
        /* always goes to front of list */
        newh->next = id->hds;
        id->hds = newh;
        break;
    case o_COND:
        h1 = id->hds;
        last = NULL;
        while(h1->o < o_PREDELIVER)
        {
            last = h1;
            h1 = h1->next;
            if(h1 == NULL)
                break; 
        }
        if(last == NULL)
        { /* goes to front of list */
            newh->next = h1;
            id->hds = newh;
        }
        else if(h1 == NULL)
        { /* goes at end of list */
            last->next = newh;
        }
        else
        { /* goes between last and h1 */
            newh->next = h1;
            last->next = newh;
        }
        break;
    case o_PREDELIVER:
        h1 = id->hds;
        last = NULL;
        while(h1->o < o_DELIVER)
        {
            last = h1;
            h1 = h1->next;
            if(h1 == NULL)
                break; 
        }
        if(last == NULL)
        { /* goes to front of list */
            newh->next = h1;
            id->hds = newh;
        }
        else if(h1 == NULL)
        { /* goes at end of list */
            last->next = newh;
        }
        else
        { /* goes between last and h1 */
            newh->next = h1;
            last->next = newh;
        }
        break;
    case o_DELIVER:
        /* always add to the end */
        for(h1 = id->hds; h1->next != NULL; h1 = h1->next);
        h1->next = newh;
        break;
    default:
    }
}


/* private struct for lists of hostname to instance mappings */
typedef struct hostid_struct
{
    char *host;
    pool p;
    instance id;
    struct hostid_struct *next;
} *hostid, _hostid;

/* three internal lists for log, xdb, and normal (session is same instances as normal) */
hostid deliver__log = NULL;
hostid deliver__xdb = NULL;
hostid deliver__norm = NULL;

void unregister_instance(instance id,char *host)
{
    hostid prev=NULL,cur=NULL;

    log_debug(ZONE,"Unregistering %s with instance %s",host,id->id);

    switch(id->type)
    {
    case p_LOG:
        if(deliver__log->id==id&&(j_strcmp(deliver__log->host,host)==0||(host==NULL&&deliver__log->host==NULL)))
        {
            cur=deliver__log;
            deliver__log=deliver__log->next;
            pool_free(cur->p);
            return;
        }
        cur=deliver__log;
        break;
    case p_XDB:
        if(deliver__xdb->id==id&&(j_strcmp(deliver__xdb->host,host)==0||(host==NULL&&deliver__xdb->host==NULL)))
        {
            cur=deliver__xdb;
            deliver__xdb=deliver__xdb->next;
            pool_free(cur->p);
            return;
        }
        cur=deliver__xdb;
        break;
    case p_NORM:
    case p_ROUTE:
        if(deliver__norm->id==id&&(j_strcmp(deliver__norm->host,host)==0||(host==NULL&&deliver__norm->host==NULL)))
        {
            cur=deliver__norm;
            deliver__norm=deliver__norm->next;
            pool_free(cur->p);
            return;
        }
        cur=deliver__norm;
        break;
    default:
    }

    for(;cur!=NULL;prev=cur,cur=cur->next)
    {
        if(cur->id==id&&(j_strcmp(cur->host,host)==0||(host==NULL&&cur->host==NULL)))
        {
            prev->next=cur->next;
            cur->next=NULL;
            pool_free(cur->p);
            break;
        }
    }

}

/* register an instance into the delivery tree */
void register_instance(instance id, char *host)
{
    hostid newh;
    hostid cur;
    pool p;

    log_debug(ZONE,"Registering %s with instance %s",host,id->id);

    /* create and setup */
    p=pool_new();
    newh = pmalloc_x(p, sizeof(_hostid), 0);
    newh->p=p;
    newh->host = pstrdup(p,host);
    newh->id = id;

    /* hook into global */
    switch(id->type)
    {
    case p_LOG:
        /* check if it's already registered */
        for(cur=deliver__log;cur!=NULL;cur=cur->next)
        {
            if(cur->id==id)
            {
                if(j_strcmp(host,cur->host)==0)
                { /* already registered */
                    pool_free(p);
                    return;
                }
            }
        }
        newh->next = deliver__log;
        deliver__log = newh;
        break;
    case p_XDB:
        /* check if it's already registered */
        for(cur=deliver__xdb;cur!=NULL;cur=cur->next)
        {
            if(cur->id==id)
            {
                if(j_strcmp(host,cur->host)==0)
                { /* already registered */
                    pool_free(p);
                    return;
                }
            }
        }
        newh->next = deliver__xdb;
        deliver__xdb = newh;
        break;
    case p_NORM:
    case p_ROUTE:
        /* check if it's already registered */
        for(cur=deliver__norm;cur!=NULL;cur=cur->next)
        {
            if(cur->id==id)
            {
                if(j_strcmp(host,cur->host)==0)
                { /* already registered */
                    pool_free(p);
                    return;
                }
            }
        }
        newh->next = deliver__norm;
        deliver__norm = newh;
        break;
    default:
    }
}

/* bounce on the delivery, use the result to better gague what went wrong */
void deliver_fail(dpacket p, char *err)
{
    terror t;
    char message[MAX_LOG_SIZE];

    log_debug(ZONE,"delivery failed (%s)",err);

    if(p==NULL) return;

    switch(p->type)
    {
    case p_LOG:
        /* stderr and drop */
        snprintf(message, MAX_LOG_SIZE, "WARNING!  Logging Failed: %s\n",xmlnode2str(p->x));
        fprintf(stderr, "%s\n", message);
        pool_free(p->p);
        break;
    case p_XDB:
        /* log_warning and drop */
        log_warn(p->host,"dropping an xdb request for %s",xmlnode_get_attrib(p->x,"to"));
        pool_free(p->p);
        break;
    case p_ROUTE:
        /* route packet bounce */
        if(j_strcmp(xmlnode_get_attrib(p->x,"type"),"error") == 0)
        {   /* already bounced once, drop */
            log_warn(p->host,"dropping a routed packet to %s from %s: %s",xmlnode_get_attrib(p->x,"to"),xmlnode_get_attrib(p->x,"from"),err);
            pool_free(p->p);
        }else{
            log_notice(p->host,"bouncing a routed packet to %s from %s: %s",xmlnode_get_attrib(p->x,"to"),xmlnode_get_attrib(p->x,"from"),err);

            /* turn into an error and bounce */
            jutil_tofrom(p->x);
            xmlnode_put_attrib(p->x,"type","error");
            xmlnode_put_attrib(p->x,"error",err);
            deliver(dpacket_new(p->x),NULL);
        }
        break;
    case p_NORM:
        /* normal packet bounce */
        if(j_strcmp(xmlnode_get_attrib(p->x,"type"),"error") == 0)
        { /* can't bounce an error */
            log_warn(p->host,"dropping a packet to %s from %s: %s",xmlnode_get_attrib(p->x,"to"),xmlnode_get_attrib(p->x,"from"),err);
            pool_free(p->p);
        }else{
            log_notice(p->host,"bouncing a packet to %s from %s: %s",xmlnode_get_attrib(p->x,"to"),xmlnode_get_attrib(p->x,"from"),err);

            /* turn into an error */
            if(err == NULL)
            {
                jutil_error(p->x,TERROR_EXTERNAL);
            }else{
                t.code = 502;
                t.msg[0] = '\0';
                strcat(t.msg,err); /* c sucks */
                jutil_error(p->x,t);
            }
            deliver(dpacket_new(p->x),NULL);
        }
        break;
    default:
    }
}

/* actually perform the delivery to an instance */
result deliver_instance(instance i, dpacket p)
{
    handel h, hlast;
    result r, best = r_NONE;
    dpacket pig = p;

    if(i == NULL)
    {
        deliver_fail(p, "Unable to deliver, destination unknown");
        return r_ERR;
    }

    log_debug(ZONE,"delivering to instance '%s'",i->id);

    /* try all the handlers */
    hlast = h = i->hds;
    while(h != NULL)
    {
        /* there may be multiple delivery handlers, make a backup copy first if we have to */
        if(h->o == o_DELIVER && h->next != NULL)
            pig = dpacket_copy(p);

        /* call the handler */
        r = (h->f)(i,p,h->arg);

        if(r > best) /* track the best result */
            best = r;

        /* if a non-delivery handler says it handled it, we have to be done */
        if(h->o != o_DELIVER && r == r_DONE)
            break;

        /* if a conditional handler wants to halt processing */
        if(h->o == o_COND && r == r_LAST)
            break;

        /* deal with that backup copy we made */
        if(h->o == o_DELIVER && h->next != NULL)
        {
            if(r == r_DONE) /* they ate it, use copy */
                p = pig;
            else
                pool_free(pig->p); /* they never used it, trash copy */
        }

        /* unregister this handler */
        if(r == r_UNREG)
        {
            if(h == i->hds)
            { /* removing the first in the list */
                i->hds = h->next;
                pool_free(h->p);
                hlast = h = i->hds;
            }else{ /* removing from anywhere in the list */
                hlast->next = h->next;
                pool_free(h->p);
                h = hlast->next;
            }
            continue;
        }

        hlast = h;
        h = h->next;
    }

    /* the packet is still valid if best != r_DONE */
    return best;
}

hostid deliver_get_next_hostid(hostid cur, char *host)
{
    while(cur != NULL)

    {
        if(host != NULL && cur->host != NULL && strcmp(cur->host,host) == 0 && cur->id->hds != NULL)
            break; /* matched hostname */
        if(host == NULL && cur->host == NULL)
            break; /* all-matching instance */
        cur = cur->next;
    }
    return cur;
}

result deliver_hostid(hostid cur, char *host, dpacket inp, result inbest)
{
    hostid next;
    result best = r_NONE;
    dpacket p = inp;

    if(cur == NULL || p == NULL) return inbest;

    /* get the next match, if there is one make a copy of the packet */
    next = deliver_get_next_hostid(cur->next, host);
    if(next != NULL)
        p = dpacket_copy(p);

    /* deliver to the current one */
    best = deliver_instance(cur->id, p);

    /* if we made a copy and it was not used */
    if(next != NULL && best != r_DONE)
        pool_free(p->p);

    /* track the highest result */
    if(best > inbest)
        inbest = best;

    if(next == NULL)
        return best;

    /* if there was another match, (tail) recurse to it with the copy */
    return deliver_hostid(next, host, inp, best);
}

/* deliver the packet, where all the smarts happen, take the sending instance as well */
void deliver(dpacket p, instance i)
{
    hostid list = NULL, cur;
    result best = r_NONE;
    char *host;
    xmlnode x;

    if(deliver__flag == 1 && p == NULL && i == NULL)
    { /* begin delivery of postponed messages */
        deliver_msg d;
        while((d=(deliver_msg)pth_msgport_get(deliver__mp))!=NULL)
        {
            deliver(d->p,d->i);
        }
        pth_msgport_destroy(deliver__mp);
        deliver__mp = NULL;
        deliver__flag = -1; /* disable all queueing crap */
    }

    /* Ensure the packet is valid */
    if (p == NULL)
	 return;

    /* Get the host */
    host = p->host;

    log_debug(ZONE,"DELIVER %d:%s %s",p->type,p->host,xmlnode2str(p->x));

    /* based on type, pick instance list */
    switch(p->type)
    {
    case p_LOG:
        list = deliver__log;
        break;
    case p_XDB:
        if(xmlnode_get_attrib(p->x, "from") == NULL && i != NULL && p->id->resource != NULL && j_strcmp(host,"-internal") == 0 && j_strcmp(p->id->user,"config") == 0)
        { /* no from="" attrib is a performance flag, and config@-internal means it's a special xdb request to get data from the config file */
            log_debug(ZONE,"processing xdb configuration request %s",xmlnode2str(p->x));
            for(x = xmlnode_get_firstchild(i->x); x != NULL; x = xmlnode_get_nextsibling(x))
            {
                if(j_strcmp(xmlnode_get_attrib(x,"xmlns"),p->id->resource) != 0)
                    continue;

                /* insert results */
                xmlnode_insert_tag_node(p->x, x);
            }

            /* reformat packet as a reply */
            xmlnode_put_attrib(p->x,"type","result");
            jutil_tofrom(p->x);
            p->type = p_NORM;

            /* deliver back to the sending instance */
            deliver_instance(i, p);
            /* XXX i guess we assume that the instance handled it :) should log error */
            return;
        }
        else if(xmlnode_get_attrib(p->x, "from") == NULL && i != NULL && p->id->resource != NULL && j_strcmp(host,"-internal") == 0 && j_strcmp(p->id->user,"host") == 0)
        { /* dynamic register_instance crap */
            register_instance(i,p->id->resource); 
        }
        else if(xmlnode_get_attrib(p->x, "from") == NULL && i != NULL && p->id->resource != NULL && j_strcmp(host,"-internal") == 0 && j_strcmp(p->id->user,"unhost") == 0)
        { /* dynamic register_instance crap */
            unregister_instance(i,p->id->resource); 
        }
        list = deliver__xdb;
        break;
    case p_NORM:
    case p_ROUTE:
        list = deliver__norm;
        break;
    default:
    }


    if(deliver__flag == 0)
    { /* postpone delivery till later */
        deliver_msg d = pmalloco(xmlnode_pool(p->x) ,sizeof(_deliver_msg));
        
        if(deliver__mp == NULL)
            deliver__mp = pth_msgport_create("deliver__");
        
        d->i = i;
        d->p = p;
        
        pth_msgport_put(deliver__mp, (void*)d);
        return;
    }

    /* XXX optimize by having seperate lists for instances for hosts and general ones (NULL) */

    cur = deliver_get_next_hostid(list, host);
    if(cur == NULL && p->type != p_ROUTE) /* if there are no exact matching ones (and this is not a routed packet) */
    {
        host = NULL;
        cur = deliver_get_next_hostid(list, host);
    }

    if(cur != NULL)
        best = deliver_hostid(cur, host, p, best);

    /* if nobody actually handled it, we've got problems */
    if(best != r_DONE)
    {
        if(best == r_ERR)
            deliver_fail(p, "Server Delivery Error");
        else
            deliver_fail(p, "Server Configuration Error");
    }
    
}

dpacket dpacket_new(xmlnode x)
{
    dpacket p;
    char *str;

    if(x == NULL)
        return NULL;

    /* create the new packet */
    p = pmalloc_x(xmlnode_pool(x),sizeof(_dpacket),0);
    p->x = x;
    p->p = xmlnode_pool(x);

    /* determine it's type */
    p->type = p_NORM;
    if(*(xmlnode_get_name(x)) == 'r')
        p->type = p_ROUTE;
    else if(*(xmlnode_get_name(x)) == 'x')
        p->type = p_XDB;
    else if(*(xmlnode_get_name(x)) == 'l')
        p->type = p_LOG;

    /* xdb results are shipped as normal packets */
    if(p->type == p_XDB && (str = xmlnode_get_attrib(p->x,"type")) != NULL && *str == 'r')
        p->type = p_NORM;

    /* determine who to route it to, overriding the default to="" attrib only for logs where we use from */
    if(p->type == p_LOG)
        p->id = jid_new(p->p, xmlnode_get_attrib(x, "from"));
    else
        p->id = jid_new(p->p, xmlnode_get_attrib(x, "to"));

    if(p->id == NULL)
    {
        log_warn(NULL,"Packet Delivery Failed, invalid packet, dropping %s",xmlnode2str(x));
        xmlnode_free(x);
        return NULL;
    }

    /* make sure each packet has the basics, norm has a to/from, log has a type, xdb has a full id */
    switch(p->type)
    {
    case p_LOG:
        if(xmlnode_get_attrib(x,"type")==NULL)
            p=NULL;
        break;
    case p_XDB:
        if(p->id->server==NULL||p->id->resource==NULL)
            p=NULL;
        break;
    case p_NORM:
        if(xmlnode_get_attrib(x,"to")==NULL||xmlnode_get_attrib(x,"from")==NULL)
            p=NULL;
        break;
    case p_ROUTE:
        if(xmlnode_get_attrib(x,"to")==NULL)
            p=NULL;
        break;
    case p_NONE:
        p=NULL;
        break;
    }
    if(p==NULL)
    {
        log_warn(NULL,"Packet Delivery Failed, invalid packet, dropping %s",xmlnode2str(x));
        xmlnode_free(x);
        return NULL;
    }

    p->host = p->id->server;
    return p;
}

dpacket dpacket_copy(dpacket p)
{
    dpacket p2;

    p2 = dpacket_new(xmlnode_dup(p->x));
    return p2;
}




