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
 *
 *  sessions.c -- handle messages to and from user sessions
 *
 *  1.0pre1
 *  Changes to the threading model: Session packets are now handled
 *  by generic worker threads. The js_session_to and _from functions
 *  start these for incoming packets. When one frees up it goes in to the
 *  pool of idle threads. spackets are dispatched to the worker threads 
 *  via pth message ports.
 *
 */

#include "jsm.h"

void _js_session_start(void *arg);
void _js_session_to(void *arg);
void _js_session_from(void *arg);
void _js_session_end(void *arg);

/*
 *  js_session_new -- creates a new session, registers the resource for it
 *  
 *  Sets up all the data associated with the new session, then send it a 
 *  start spacket, which basically notifies all modules about the new session
 *
 *  returns
 *      a pointer to the new session 
 */
session js_session_new(jsmi si, jid owner, jid sid)
{
    pool p;         /* a memory pool for the session */
    session s;      /* the session being created */
    jid uid;        /* a general jid for the session - ie with no resource */
    int i;
    udata u;

    /* screen out illegal calls */
    if(sid == NULL || owner == NULL || owner->resource == NULL || (u = js_user(si,owner,NULL)) == NULL)
        return NULL;

    log_debug(ZONE,"session_create %s at %s",jid_full(owner),jid_full(sid));

    /* create session */
    p = pool_heap(2*1024);
    pool_label(p,jid_full(owner),0);
    s = pmalloc(p, sizeof(struct session_struct));
    s->p = p;
    s->si = si;

    /* save the remote session id */
    s->sid = jid_new(p, jid_full(sid));

    /* session identity */
    s->id = jid_new(p, jid_full(owner));
    uid = jid_new(p, jid_full(owner));
    jid_set(uid, NULL, JID_RESOURCE);
    s->uid = uid;
    s->res = pstrdup(p, owner->resource);
    s->u = u;

    /* default settings */
    s->exit_flag = 0;
    s->roster = 0;
    s->priority = -1;
    s->presence = jutil_presnew(JPACKET__UNAVAILABLE,NULL,NULL);
    xmlnode_put_attrib(s->presence,"from",jid_full(s->id));
    s->c_in = s->c_out = 0;
    s->q = mtq_new(s->p);
    for(i = 0; i < es_LAST; i++)
        s->events[i] = NULL;

    /* remove any other session w/ this resource */
    js_session_end(js_session_get(s->u, owner->resource), "Replaced by new connection");

    /* make sure we're linked with the user */
    s->next = s->u->sessions;
    s->u->sessions = s;
    s->u->scount++;

    /* start it */
    mtq_send(s->q, s->p, _js_session_start, (void *)s);

    return s;
}

/*
 *  js_session_end -- shut down the session
 *  
 *  This function gets called when the user disconnects or when the server shuts
 *  down. It changes the user's presence to offline, cleans up the session data
 *  and sends an end spacket
 *
 *  parameters
 *  	s -- the session to end
 *      reason -- the reason the session is shutting down (for logging)
 *
 */
void js_session_end(session s, char *reason)
{
    xmlnode x;      /* new presence data */
    session cur;    /* used to iterate over the user's session list
                       when removing the session from the list */

    /* ignore illegal calls */
    if(s == NULL || s->exit_flag == 1 || reason == NULL)
        return;

    /* log the reason the session ended */
    log_debug(ZONE,"end %d '%s'",s,reason);

    /* flag the session to exit ASAP */
    s->exit_flag = 1;

    /* make sure we're not the primary session */
    s->priority = -1;

    /* if the last known presence was available, update it */
    if(s->presence != NULL && j_strcmp(xmlnode_get_attrib(s->presence, "type"), "unavailable") != 0)
    {

        /* create a new presence packet with the reason the user is unavailable */
        x = jutil_presnew(JPACKET__UNAVAILABLE,NULL,reason);
        xmlnode_put_attrib(x,"from",jid_full(s->id));

        /* free the old presence packet */
        xmlnode_free(s->presence);

        /* install the presence */
        s->presence = x;

    }

    /*
     * remove this session from the user's session list --
     * first check if this session is at the head of the list
     */
    if(s == s->u->sessions)
    {
        /* yup, just bump up the next session */
        s->u->sessions = s->next;

    }else{

        /* no, we have to traverse the list to find it */
        for(cur = s->u->sessions; cur->next != s; cur = cur->next);
        cur->next = s->next;

    }

    /* so it doesn't get freed */
    s->u->ref++;

    /* tell it to exit */
    mtq_send(s->q, s->p, _js_session_end, (void *)s);

}

/* child that starts a session */
void _js_session_start(void *arg)
{
    session s = (session)arg;

    /* let the modules go to it */
    js_mapi_call(s->si, e_SESSION, NULL, s->u, s);

    /* log the start time of the session */
    s->started = time(NULL);
}

/* child that handles packets from the user */
void _js_session_from(void *arg)
{
    jpacket p = (jpacket)arg;
    session s = (session)(p->aux1);

    /* if this session is dead */
    if(s->exit_flag)
    {
        /* send the packet into oblivion */
        xmlnode_free(p->x);
        return;
    }

    /* at least we must have a valid packet */
    if(p->type == JPACKET_UNKNOWN)
    {
        /* if not,s send an error to the session */
        jutil_error(p->x,TERROR_BAD);
        jpacket_reset(p);
        js_session_to(s,p);
        return;
    }

    /* debug message */
    log_debug(ZONE,"THREAD:SESSION:FROM received a packet!");

    /* increment packet out count */
    s->c_out++;

    /* make sure we have our from set correctly for outgoing packets */
    if(jid_cmp(p->from,s->uid) != 0 && jid_cmp(p->from,s->id) != 0)
    {
        /* nope, fix it */
        xmlnode_put_attrib(p->x,"from",jid_full(s->id));
        p->from = jid_new(p->p,jid_full(s->id));
    }

    /* let the modules have their heyday */
    if(js_mapi_call(NULL, es_OUT,  p, s->u, s))
        return;

    /* no module handled it, so make sure there's a to attribute */
    if(p->to == NULL)
    {
        /* nope, make one based on the from attribute */
        xmlnode_put_attrib(p->x,"to",p->from->server);
        p->to = jid_new(p->p,p->from->server);
    }

    /* pass these to the general delivery function */
    js_deliver(s->si, p);

}

/* child that handles packets to the user */
void _js_session_to(void *arg)
{
    jpacket p = (jpacket)arg;
    session s = (session)(p->aux1);

    /* if this session is dead... */
    if(s->exit_flag)
    {
        /* ... and the packet is a message */
        if(p->type == JPACKET_MESSAGE)
            js_deliver(s->si, p);
        else /* otherwise send it to oblivion */
            xmlnode_free(p->x);
        return;
    }

    /* debug message */
    log_debug(ZONE,"THREAD:SESSION:TO received data from %s!",jid_full(p->from));

    /* increment packet in count */
    s->c_in++;

    /* let the modules have their heyday */
    if(js_mapi_call(NULL, es_IN, p, s->u, s))
        return;

    /* we need to check again, s->exit_flag *could* have changed within the modules at some point */
    if(s->exit_flag)
    {
        /* deliver that packet if it was a message, and sk'daddle */
        if(p->type == JPACKET_MESSAGE)
            js_deliver(s->si, p);
        else
            xmlnode_free(p->x);
        return;
    }

    /* wrap in a route and deliver outgoing for this session */
    p->x = xmlnode_wrap(p->x,"route");
    xmlnode_put_attrib(p->x, "to", jid_full(s->sid));
    xmlnode_put_attrib(p->x, "from", jid_full(s->uid));
    deliver(dpacket_new(p->x), s->si->i);
}

/* child that cleans up a session */
void _js_session_end(void *arg)
{
    session s = (session)arg;
    xmlnode x;

    /* debug message */
    log_debug(ZONE,"THREAD:SESSION exiting");

    /* decrement the user's session count */
    s->u->scount--;

    /* make sure the service knows the session is gone */
    if(j_strcmp(xmlnode_get_tag_data(s->presence,"state"),"Disconnected") != 0)
    {   /* if the offline presence was "Disconnected", that implies that it was the client service, and we don't really need to tell it again */
         x = xmlnode_new_tag("route");
         xmlnode_put_attrib(x, "type", "error");
         xmlnode_put_attrib(x, "to", jid_full(s->sid));
         xmlnode_put_attrib(x, "from", jid_full(s->id));
         deliver(dpacket_new(x), s->si->i);
    }

    /* let the modules have their heyday */
    js_mapi_call(NULL, es_END, NULL, s->u, s);

    /* let the user struct go  */
    s->u->ref--;

    /* free the session's presence state */
    xmlnode_free(s->presence);

    /* free the session's memory pool */
    pool_free(s->p);
}

/*
 *  js_session_get -- find the session for a resource
 *  
 *  Given a user and a resource, find the corresponding session
 *  if the user is logged in. Otherwise return NULL.
 *
 *  parameters
 *  	user -- the user's udata record
 *      res -- the resource to search for
 *
 *  returns
 *      a pointer to the session if the user is logged in
 *      NULL if the user isn't logged in on this resource
 */
session js_session_get(udata user, char *res)
{
    session cur;    /* session pointer */

    /* screen out illeagal calls */
    if(user == NULL || res == NULL)
        return NULL;

    /* find the session and return it*/
    for(cur = user->sessions; cur != NULL; cur = cur->next)
        if(j_strcmp(res, cur->res) == 0)
            return cur;

    /* if we got this far, there is no session */
    return NULL;

}

/*
 *  js_session_primary -- find the primary session for the user
 *  
 *  Scan through a user's sessions to find the session with the
 *  highest priority and return a pointer to it.
 *
 *  parameters
 *  	user -- user data for the user in question
 *
 *  returns
 *      a pointer to the primary session if the user is logged in
 *      NULL if there are no active sessions
 */
session js_session_primary(udata user)
{
    session cur, top;

    /* ignore illeagal calls, or users with no sessions */
    if(user == NULL || user->sessions == NULL)
        return NULL;

    /* find primary session */
    top = user->sessions;
    for(cur = top; cur != NULL; cur = cur->next)
        if(cur->priority > top->priority)
            top = cur;

    /* return it if it's active */
    if(top->priority >= 0)
        return top;

    else /* otherwise there's no active session */
        return NULL;

}

void js_session_to(session s, jpacket p)
{
    /* queue the call to child, hide session in packet */
    p->aux1 = (void *)s;
    mtq_send(s->q, p->p, _js_session_to, (void *)p);
}

void js_session_from(session s, jpacket p)
{
    /* queue the call to child, hide session in packet */
    p->aux1 = (void *)s;
    mtq_send(s->q, p->p, _js_session_from, (void *)p);
}

