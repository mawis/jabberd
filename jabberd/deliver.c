#include "jabberd.h"

/* register a function to handle delivery for this idnode */
void hdreg(idnode id, order o, hdgene f, void *arg)
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
    case o_FIRST:
        newh->next = id->hds;
        id->hds = newh;
        break;
    case o_ANY:
        for(h1 = id->hds; h1->next != NULL && h1->next->o != o_FIRST; h1 = h1->next);
        if(h1->next == NULL)
        {
            h1->next = newh;
        }else{
            newh->next = h1->next;
            h1->next = newh;
        }
        break;
    case o_LAST:
        for(h1 = id->hds; h1->next != NULL; h1 = h1->next);
        h1->next = newh;
        break;
    default:
    }
}


/* private struct for lists of hostname to idnode mappings */
typedef struct hostid_struct
{
    char *host;
    idnode id;
    struct hostid_struct *next;
} *hostid, _hostid;

/* three internal lists for log, xdb, and normal (session is same idnodes as normal) */
hostid deliver__log = NULL;
hostid deliver__xdb = NULL;
hostid deliver__norm = NULL;
pool deliver__p = NULL;

/* register an idnode into the delivery tree */
void idreg(idnode id, char *host)
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
    case p_SESS:
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
    case p_SESS:
        break;
    }
}

/* actually perform the delivery to an idnode */
void deliver_idnode(idnode id, dpacket p)
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

/* deliver the packet, where all the smarts happen */
void deliver(dpacket p)
{
    hostid list, cur;

    /* based on type, pick idnode list */
    switch(p->type)
    {
    case p_LOG:
        list = deliver__log;
        break;
    case p_XDB:
        list = deliver__xdb;
        break;
    case p_NORM:
    case p_SESS:
        list = deliver__norm;
        break;
    default:
    }

    /* XXX optimize by having seperate lists for idnodes for hosts and general ones (NULL) */

    /* send the packet to every exact matching idnode */
    for(cur = list; cur != NULL; cur = cur->next)
        if(cur->host != NULL && strcmp(cur->host,p->host) == 0)
            deliver_idnode(cur->id, p);

    /* if it didn't get delivered at all, send the packet to idnodes that handle any host */
    if(!(p->flag_used))
        for(cur = list; cur != NULL; cur = cur->next)
            if(cur->host == NULL)
                deliver_idnode(cur->id, p);

    /* if nobody actually handled it, we've got problems */
    if(p->flag_best != r_OK)
        deliver_fail(p);
    
    /* we cleanup the packet */
    pool_free(p->p);        
}
