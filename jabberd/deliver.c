#include "jabberd.h"

/* register a function to handle delivery for this instance */
void register_phandler(instance id, order o, phandler f, void *arg)
{
    handel newh, h1;
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
        newh->next = id->hds;
        id->hds = newh;
        break;
    case o_COND:
        for(h1 = id->hds; h1->next != NULL && h1->next->o != o_COND; h1 = h1->next);
        if(h1->next == NULL)
        {
            h1->next = newh;
        }else{
            newh->next = h1->next;
            h1->next = newh;
        }
        break;
    case o_PREDELIVER:
        for(h1 = id->hds; h1->next != NULL && h1->next->o != o_PREDELIVER; h1 = h1->next);
        if(h1->next == NULL)
        {
            h1->next = newh;
        }else{
            newh->next = h1->next;
            h1->next = newh;
        }
        break;
    case o_DELIVER:
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
    instance id;
    struct hostid_struct *next;
} *hostid, _hostid;

/* three internal lists for log, xdb, and normal (session is same instances as normal) */
hostid deliver__log = NULL;
hostid deliver__xdb = NULL;
hostid deliver__norm = NULL;
pool deliver__p = NULL;

/* register an instance into the delivery tree */
void register_instance(instance id, char *host)
{
    hostid newh;

    /* if first time */
    if(deliver__p == NULL) deliver__p = pool_new();

    /* create and setup */
    newh = pmalloc_x(deliver__p, sizeof(_hostid), 0);
    newh->host = pstrdup(deliver__p,host);
    newh->id = id;

    /* hook into global */
    switch(id->type)
    {
    case p_LOG:
        newh->next = deliver__log;
        deliver__log = newh;
        break;
    case p_XDB:
        newh->next = deliver__xdb;
        deliver__xdb = newh;
        break;
    case p_NORM:
        newh->next = deliver__norm;
        deliver__norm = newh;
        break;
    default:
    }
    id->flag_used++;
}

/* bounce on the delivery, use the result to better gague what went wrong */
void deliver_fail(dpacket p, result r)
{

    log_debug(ZONE,"delivery failed (%d)",r);

    switch(p->type)
    {
    case p_LOG:
        /* stderr and drop */
        break;
    case p_XDB:
        /* empty result */
        break;
    case p_NORM:
        /* normal packet bounce */
        break;
    default:
    }
}

/* actually perform the delivery to an instance */
result deliver_instance(instance id, dpacket p, result inbest)
{
    handel h, hlast;
    result r, best = r_NONE;
    dpacket pig = p;

    log_debug(ZONE,"delivering to instance '%s'",id->id);

    /* try all the handlers */
    hlast = h = id->hds;
    while(h != NULL)
    {
        /* there may be multiple delivery handlers, make a backup copy first if we have to */
        if(h->o == o_DELIVER && h->next != NULL)
            pig = dpacket_copy(p);

        /* call the handler */
        r = (h->f)(id,p,h->arg);

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
            if(h == id->hds)
            { /* removing the first in the list */
                id->hds = h->next;
                pool_free(h->p);
                hlast = h = id->hds;
            }else{ /* removing from anywhere in the list */
                hlast->next = h->next;
                pool_free(h->p);
                h = hlast->next;
            }
        }

        hlast = h;
        h = h->next;
    }

    /* if this instance never handled the packet, we still need to free it since we're expected to have delivered it */
    if(best != r_DONE)
        pool_free(p->p);

    if(best > inbest)
        return best;
    else
        return inbest;
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

result deliver_hostid(hostid cur, char *host, dpacket p, result best)
{
    hostid next;
    dpacket pig;

    if(cur == NULL || p == NULL) return best;

    /* get the next match, if there is one make a copy of the packet */
    next = deliver_get_next_hostid(cur->next, host);
    if(next != NULL)
        pig = dpacket_copy(p);

    /* deliver to the current one */
    best = deliver_instance(cur->id, p, best);

    if(next == NULL)
        return best;

    /* if there was another match, (tail) recurse to it with the copy */
    return deliver_hostid(next, host, pig, best);
}

/* deliver the packet, where all the smarts happen, take the sending instance as well */
void deliver(dpacket p, instance i)
{
    hostid list, cur;
    result best = r_NONE;
    char *host;
    xmlnode x;

    /* Ensure the packet is valid */
    if (p == NULL)
	 return;

    /* Get the host */
    host = p->host;

    /* XXX deliver() will have to queue until configuration is done, since threads may have started during config and be delivering already */

    log_debug(ZONE,"DELIVER %d:%s %s",p->type,p->host,xmlnode2str(p->x));

    /* based on type, pick instance list */
    switch(p->type)
    {
    case p_LOG:
        list = deliver__log;
        break;
    case p_XDB:
        if(xmlnode_get_attrib(p->x, "from") == NULL && i != NULL && p->id->resource != NULL && strcmp(host,"-internal") == 0 && j_strcmp(p->id->user,"config") == 0)
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
            deliver_instance(i, p, best);
            /* XXX i guess we assume that the instance handled it :) should log error */
            return;
        }
        list = deliver__xdb;
        break;
    case p_NORM:
        list = deliver__norm;
        break;
    default:
    }

    /* XXX optimize by having seperate lists for instances for hosts and general ones (NULL) */

    cur = deliver_get_next_hostid(list, host);
    if(cur == NULL) /* if there are no exact matching ones */
    {
        host = NULL;
        cur = deliver_get_next_hostid(list, host);
    }

    if(cur != NULL)
        best = deliver_hostid(cur, host, p, best);

    /* if nobody actually handled it, we've got problems */
    if(best != r_DONE)
        deliver_fail(p, best);
    
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
    if(*(xmlnode_get_name(x)) == 'l')
        p->type = p_LOG;
    else if(*(xmlnode_get_name(x)) == 'x')
        p->type = p_XDB;

    /* xdb results are shipped as normal packets */
    if(p->type == p_XDB && (str = xmlnode_get_attrib(p->x,"type")) != NULL && *str == 'r')
        p->type = p_NORM;

    /* determine who to route it to, overriding the default to="" attrib only for sto="" special case */
    if(p->type == p_NORM && xmlnode_get_attrib(x, "sto") != NULL)
        p->id = jid_new(p->p, xmlnode_get_attrib(x, "sto"));
    else
        p->id = jid_new(p->p, xmlnode_get_attrib(x, "to"));

    if(p->id == NULL)
        return NULL;

    /* XXX be more stringent, make sure each packet has the basics, norm has a to/from, log has a type, xdb has a full id */

    p->host = p->id->server;
    return p;
}

dpacket dpacket_copy(dpacket p)
{
    dpacket p2;

    p2 = dpacket_new(xmlnode_dup(p->x));
    return p2;
}




