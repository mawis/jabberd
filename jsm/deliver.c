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

#include "jsm.h"


/* takes any packet and attempts to deliver it to the correct session/thread */
/* must have a valid to/from address already before getting here */
void js_deliver_local(jsmi si, jpacket p, HASHTABLE ht)
{
    udata user = NULL;
    session s = NULL;

    /* first, collect some facts */
    user = js_user(si, p->to, ht);
    s = js_session_get(user, p->to->resource);

log_debug(ZONE,"");
    /* let some modules fight over it */
    if(js_mapi_call(si, e_DELIVER, p, user, s))
        return;

log_debug(ZONE,"");
    if(p->to->user == NULL)
    { /* this is for the server */
        js_psend(si->mpserver,p);
        return;
    }

log_debug(ZONE,"");
    if(s != NULL)
    { /* it's sent right to the resource */
        js_session_to(s, p);
        return;
    }

log_debug(ZONE,"");
    if(user != NULL)
    { /* valid user, but no session */
        p->aux1 = (void *)user; /* performance hack, we already know the user */
        user->ref++; /* so it doesn't get cleaned up before the thread gets it */
        js_psend(si->mpoffline,p);
        return;
    }

log_debug(ZONE,"");
    /* no user, so bounce the packet */
    js_bounce(si,p->x,TERROR_NOTFOUND);
}


result js_packet(instance i, dpacket p, void *arg)
{
    jsmi si = (jsmi)arg;
    jpacket jp;
    HASHTABLE ht;
    jid sto;
    session s;
    xmlnode x;

    jp = jpacket_new(p->x);

    log_debug(ZONE,"(%X)incoming packet %s",si,xmlnode2str(jp->x));

    /* make sure this hostname is in the master table */
    if((ht = (HASHTABLE)ghash_get(si->hosts,p->host)) == NULL)
    {
        /* XXX make USERS_PRIME configurable */
        ht = ghash_create(USERS_PRIME,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
        log_debug(ZONE,"creating user hash %X for %s",ht,p->host);
        ghash_put(si->hosts,pstrdup(si->p,p->host), (void *)ht);
        log_debug(ZONE,"checking %X",ghash_get(si->hosts,p->host));
    }

    /* if this is a session packet */
    if((sto = jid_new(p->p,xmlnode_get_attrib(p->x,"sto"))) != NULL)
    {
        if(sto->user == NULL && jp->type == JPACKET_IQ && (jpacket_subtype(jp) == JPACKET__GET || jpacket_subtype(jp) == JPACKET__SET))
        { /* only valid iq reqs apply */
            js_authreg_send(si, jp);
            return r_DONE;
        }

        /* this is a packet to be processed as outgoing for a session */

        /* attempt to locate the session */
        s = js_session_get(js_user(si, sto, ht),sto->resource);

        /* hide the special session attribs */
        xmlnode_hide_attrib(jp->x,"sto");
        xmlnode_hide_attrib(jp->x,"sfrom");

        /* if it's a 510 error */
        if(jpacket_subtype(jp) == JPACKET__ERROR && (x = xmlnode_get_tag(jp->x,"error?code=510")) != NULL)
        {
            if(s != NULL) /* obviously the session should end pronto */
                js_session_end(s, "Disconnected");

            /* if this was a message, it should have been delievered to that session, store offline */
            if(jp->type == JPACKET_MESSAGE)
            {
                xmlnode_put_attrib(jp->x,"type",xmlnode_get_attrib(x,"type")); /* restore the original type */
                xmlnode_hide(x); /* remove our special error type */
                jpacket_reset(jp);
                if(jp->to != NULL && jp->from != NULL) /* 510 error msgs from the socket manager itself aren't going to have a to/from */
                {
                    js_deliver_local(si, jp, ht); /* (re)deliver it locally again, should go to another session or offline */
                    return r_DONE;
                }
            }

            /* drop and return */
            log_notice(p->host, "dropping a bounced session packet to %s", jid_full(sto));
            xmlnode_free(jp->x);
            return r_DONE;
        }

        if(s != NULL)
        {   /* just pass to the session normally */
            js_session_from(s, jp);
        }else{
            /* send an error msg to the client manager to make sure it knows there's no session */
            x = xmlnode_new_tag("message");
            xmlnode_put_attrib(x,"sto",xmlnode_get_attrib(jp->x,"sfrom"));
            jutil_error(x, TERROR_DISCONNECTED);
            deliver(dpacket_new(x), NULL);

            /* XXX what should we really do here? if this is a message the client was trying to send, and there's no session, I'm not sure :) */

            /* drop packets w/o session */
            log_notice(sto->server,"Dropping %s packet intended for session %s",xmlnode_get_name(jp->x),jid_full(sto));
            xmlnode_free(jp->x);
        }
        return r_DONE;
    }

    /* normal server-server packet, should we make sure it's not spoofing us?  if so, if ghash_get(p->to->server) then bounce w/ security error */

    js_deliver_local(si, jp, ht);

    return r_DONE;
}


/* NOTE: any jpacket sent to deliver *MUST* match jpacket_new(p->x),
 * jpacket is simply a convenience wrapper
 */
void js_deliver(jsmi si, jpacket p)
{
    HASHTABLE ht;

    if(p->to == NULL)
    {
        log_warn(NULL,"jsm: Invalid Recipient, returning data %s",xmlnode2str(p->x));
        js_bounce(si,p->x,TERROR_BAD);
        return;
    }

    if(p->from == NULL)
    {
        log_warn(NULL,"jsm: Invalid Sender, discarding data %s",xmlnode2str(p->x));
        xmlnode_free(p->x);
        return;
    }

    log_debug(ZONE,"deliver(to[%s],from[%s],type[%d],packet[%s])",jid_full(p->to),jid_full(p->from),p->type,xmlnode2str(p->x));

    /* external to us */
    if((ht = (HASHTABLE)ghash_get(si->hosts,p->to->server)) != NULL)
    {
        js_deliver_local(si, p, ht);
        return;
    }
    deliver(dpacket_new(p->x), si->i);

}


void js_psend(pth_msgport_t mp, jpacket p)
{
    jpq q;

    if(p == NULL || mp == NULL)
        return;

    log_debug(ZONE,"psending to %X packet %X",mp,p);

    q = pmalloc(p->p, sizeof(_jpq));
    q->p = p;

    pth_msgport_put(mp, (pth_message_t *)q);
}


/* for fun, a tidbit from late nite irc (ya had to be there)
<temas> What is 1+1
<temas> Why did you hardcode stuff
<temas> Was the movie good?
<temas> DId the nukes explode?
*/
