/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  Jabber
 *  Copyright (C) 1998-1999 The Jabber Team http://jabber.org/
 */

#include "jabberd.h"
int deliver__flag=0;
pth_msgport_t deliver__mp=NULL;
typedef struct deliver_mp_st
{
    pth_message_t head;
    instance i;
    dpacket p;
} _deliver_msg,*deliver_msg;

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
        for(h1 = id->hds; h1->next != NULL && h1->next->o == o_PRECOND; h1 = h1->next);
        if(h1->next == NULL)
        {
            h1->next = newh;
        }else{
            newh->next = h1->next;
            h1->next = newh;
        }
        break;
    case o_PREDELIVER:
        for(h1 = id->hds; h1->next != NULL && h1->next->o != o_DELIVER; h1 = h1->next);
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
    hostid prev=NULL,cur;

    log_debug(ZONE,"Unregistering %s with instance %s",host,id->id);

    switch(id->type)
    {
    case p_LOG:
        if(deliver__log->id==id&&j_strcmp(deliver__log->host,host)==0)
        {
            cur=deliver__log;
            deliver__log=deliver__log->next;
            pool_free(cur->p);
            return;
        }
        cur=deliver__log;
        break;
    case p_XDB:
        if(deliver__xdb->id==id&&j_strcmp(deliver__xdb->host,host)==0)
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
        if(deliver__norm->id==id&&j_strcmp(deliver__norm->host,host)==0)
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
        if(cur->id==id&&j_strcmp(cur->host,host)==0)
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
        newh->next = deliver__log;
        deliver__log = newh;
        break;
    case p_XDB:
        newh->next = deliver__xdb;
        deliver__xdb = newh;
        break;
    case p_NORM:
    case p_ROUTE:
        newh->next = deliver__norm;
        deliver__norm = newh;
        break;
    default:
    }
    id->flag_used++;
}

/* bounce on the delivery, use the result to better gague what went wrong */
void deliver_fail(dpacket p, char *err)
{
    terror t;

    log_debug(ZONE,"delivery failed (%s)",err);

    if(p==NULL) return;

    switch(p->type)
    {
    case p_LOG:
        /* stderr and drop */
        fprintf(stderr,"WARNING!  Logging Failed: %s\n",xmlnode2str(p->x));
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
            log_warn(p->host,"dropping a routed packet to %s from %s",xmlnode_get_attrib(p->x,"to"),xmlnode_get_attrib(p->x,"from"));
            pool_free(p->p);
        }else{
            log_notice(p->host,"bouncing a routed packet to %s from %s",xmlnode_get_attrib(p->x,"to"),xmlnode_get_attrib(p->x,"from"));

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
            log_warn(p->host,"dropping a packet to %s from %s",xmlnode_get_attrib(p->x,"to"),xmlnode_get_attrib(p->x,"from"));
            pool_free(p->p);
        }else{
            log_notice(p->host,"bouncing a packet to %s from %s",xmlnode_get_attrib(p->x,"to"),xmlnode_get_attrib(p->x,"from"));

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
    hostid list, cur;
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
        deliver__flag = -1; /* disable all queueing crap */
    }

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
        deliver_msg d=pmalloco(xmlnode_pool(p->x),sizeof(_deliver_msg));
        if(deliver__mp==NULL)deliver__mp=pth_msgport_create("deliver__");
        d->i=i;
        d->p=p;
        pth_msgport_put(deliver__mp,(void*)d);
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
        log_error(NULL,"Packet Delivery Failed, invalid packet, dropping %s",xmlnode2str(x));
        xmlnode_free(x);
        return NULL;
    }

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




