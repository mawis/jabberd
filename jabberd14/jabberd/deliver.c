#include "jabberd.h"

/* register a function to handle delivery for this instance */
void register_phandler(instance id, order o, phandler f, void *arg)
{
    handel newh, h1;

    /* create handel and setup */
    newh = pmalloc_x(id->p, sizeof(_handel), 0);
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
    case o_MODIFY:
        for(h1 = id->hds; h1->next != NULL && h1->next->o != o_MODIFY; h1 = h1->next);
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

void deliver_fail(dpacket p)
{
    switch(p->type)
    {
    case p_LOG:
        break;
    case p_XDB:
        break;
    case p_NORM:
        break;
    }
}

/* actually perform the delivery to an instance */
void deliver_instance(instance id, dpacket p)
{
    handel h;
    result r;

    p->flag_used++;

    /* try all the handlers */
    for(h = id->hds; h != NULL; h = h->next)
    {
        r = (h->f)(id,p,h->arg);
        if(r > p->flag_best) /* store the best response */
            p->flag_best = r;

        /* only try another one if this one passed */
        if(r == r_PASS)
            continue;

        break;
    }
}

/* deliver the packet, where all the smarts happen, take the sending instance as well */
void deliver(dpacket p, instance i)
{
    hostid list, cur;

    /* XXX once we switch to pthreads, deliver() will have to queue until configuration is done, since threads may have started during config and be delivering already */

    /* based on type, pick instance list */
    switch(p->type)
    {
    case p_LOG:
        list = deliver__log;
        break;
    case p_XDB:
        if(xmlnode_get_attrib(p->x, "from") == NULL)
        { /* no from="" attrib implies it's a special xdb request to get data from the config file */
            
        }
        list = deliver__xdb;
        break;
    case p_NORM:
        list = deliver__norm;
        break;
    default:
    }

    /* XXX optimize by having seperate lists for instances for hosts and general ones (NULL) */

    /* send the packet to every exact matching instance */
    for(cur = list; cur != NULL; cur = cur->next)
        if(cur->host != NULL && strcmp(cur->host,p->host) == 0)
            deliver_instance(cur->id, p);

    /* if it didn't get delivered at all, send the packet to instances that handle any host */
    if(!(p->flag_used))
        for(cur = list; cur != NULL; cur = cur->next)
            if(cur->host == NULL)
                deliver_instance(cur->id, p);

    /* if nobody actually handled it, we've got problems */
    if(p->flag_best != r_OK)
        deliver_fail(p);
    
    /* we cleanup the packet */
    pool_free(p->p);        
}

dpacket dpacket_new(xmlnode x)
{
    dpacket p;

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

    /* determine who to route it to, overriding the default to="" attrib only for sid special case */
    if(p->type == p_NORM && xmlnode_get_attrib(x, "sid") != NULL)
        p->id = jid_new(p->p, xmlnode_get_attrib(x, "sid"));
    else
        p->id = jid_new(p->p, xmlnode_get_attrib(x, "to"));

    if(p->id == NULL)
        return NULL;

    p->host = p->id->server;
    return p;
}
