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

/* definition of spacket types */
#define SPACKET_TO 1
#define SPACKET_FROM 2
#define SPACKET_START 3
#define SPACKET_END 4

/* spacket struct */
typedef struct spacket_struct
{
    pth_message_t head; /* the standard pth message header */
    jpacket p;          /* jabber packet */
    session s;          /* the session to deliver the packet to */
    int type;           /* the packet type */
} _spacket, *spacket;

/* private entry function for worker threads */
void *js_worker_main(void *arg);

/*
 *  js_session_worker -- return a free worker thread
 *
 *  Searches the idle pool for an available thread and
 *  returns it's message port. If there are no idle threads
 *  js_session_worker creates one and returns it's message port
 *  
 *  returns
 *      the message port of an available worker thread 
 *      
 */
pth_msgport_t js_session_worker(session s)
{
    pth_msgport_t mp;   /* message port used by the worker thread */
    int i;              /* index into the array of worker threads */

    /* first check if the session is already associated w/ a worker, to avoid out-of-order packet processing */
    if(s->worker != NULL)
        return s->worker;

    /* scan for a waiting worker */
    for(i=0;i<SESSION_WAITERS; i++)
        if(s->si->waiting[i] != NULL)
        {
            /* found an idle thread, return it */
            log_debug(ZONE,"worker fetch returning swaiters[%d] %X",i,s->si->waiting[i]);
            s->worker = s->si->waiting[i];
            return s->worker;
        }


    /* there were no idle threads, so we have to create one */
    mp = pth_msgport_create("js_worker");
    pth_spawn(PTH_ATTR_DEFAULT, js_worker_main, (void *)mp);

    /* put it in the waiting pool */
    for(i=0;i<SESSION_WAITERS; i++)
        if(s->si->waiting[i] == NULL)
        {
            s->si->waiting[i] = mp;
            break;
        }

    /* return it's message port */
    log_debug(ZONE,"worker fetch returning new swaiters[%d] %X",i,mp);
    s->worker = mp;
    return mp;

}

/*
 *  js_spacket -- send the spacket
 *  
 *  Package up a jpacket and send it to a session
 *
 *  parameters
 *      type -- the type of spacket to create
 *      s -- the session to send the packet to
 *      p -- the packet to send   
 */
void js_spacket(int type, session s, jpacket p)
{

    static pth_msgport_t unknown_mp = NULL; /* the reply port for unknown users */
    spacket q;                              /* the spacket to create */

    /* ignore calls with no session specified */
    if(s == NULL)
        return;

    /* debug message */
    log_debug(ZONE,"spacket %d to session %X packet %X",type,s,p);

    /* find the reply port if we haven't already */
    if(unknown_mp == NULL)
        unknown_mp = pth_msgport_find("js_unknown");

    /*
     *  Get the memory from wherever we can. Since the packet might
     *  be null, we may have to allocate from the session's pool. 
     */ 
    if(p != NULL)
        q = pmalloc(p->p, sizeof(_spacket));
    else
        q = pmalloc(s->p, sizeof(_spacket));

    /* fill in the fields of the spacket struct */
    q->type = type;
    q->s = s;
    q->p = p;

    /* set up the reply port for the pth message */
    q->head.m_replyport = unknown_mp;

    /* pass the packet on to the worker thread */
    pth_msgport_put(js_session_worker(s), (pth_message_t *)q);

}

/*
 *  js_session_new -- creates a new session, registers the resource for it
 *  
 *  Sets up all the data associated with the new session, then send it a 
 *  start spacket, which basically notifies all modules about the new session
 *
 *  parameters
 *  	owner -- the user that has logged in
 *      send -- a send handler
 *      arg -- an opaque argument to pass to the send handler
 *
 *  returns
 *      a pointer to the new session 
 */
session js_session_new(jid owner, session_onSend send, void *arg)
{

    pool p;         /* a memory pool for the session */
    session s;      /* the session being created */
    jid uid;        /* a general jid for the session - ie with no resource */
    int i;

    /* screen out illegal calls */
    if(owner == NULL || owner->resource == NULL)
        return NULL;

    /* hack to init the array the first time */
    if(swaiters_init)
    {
        for(i=0;i<SESSION_WAITERS;i++)
            swaiters[i] = NULL;
        swaiters_init = 0;
    }

    log_debug(ZONE,"session_create");

    /* create session */
    p = pool_heap(2*1024);
    pool_label(p,jid_full(owner),0);
    s = pmalloc(p, sizeof(struct session_struct));
    s->p = p;

    /* save the send callback for the service */
    s->send = send;
    s->arg = arg;

    /* session identity */
    s->id = jid_new(p, jid_full(owner));
    uid = jid_new(p, jid_full(owner));
    jid_set(uid, NULL, JID_RESOURCE);
    s->uid = uid;
    s->res = pstrdup(p, owner->resource);
    s->u = js_user(owner->user);

    /* default settings */
    s->exit_flag = 0;
    s->roster = 0;
    s->priority = -1;
    s->presence = jutil_presnew(JPACKET__UNAVAILABLE,NULL,NULL);
    xmlnode_put_attrib(s->presence,"from",jid_full(s->id));
    s->c_in = s->c_out = 0;
    s->m_out = s->m_in = s->m_end = NULL;
    s->worker = NULL;

    /* remove any other session w/ this resource */
    js_session_end(js_session_get(s->u, owner->resource), "Replaced by new connection");

    /* make sure we're linked with the user */
    s->next = s->u->sessions;
    s->u->sessions = s;
    s->u->scount++;

    /* start it */
    js_spacket(SPACKET_START, s, NULL);

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
    js_spacket(SPACKET_END, s, NULL);

}

/*
 *  js_session_process -- process packets sent to this thread
 *  
 *  Retrieves all packets waiting on the message port and processes
 *  them based on their type
 *
 *  parameters
 *  	mp -- pth message port to use get packets from
 *
 */
void js_session_process(pth_msgport_t mp)
{
    spacket q;          /* local reference to the packet */
    mmaster master;     /* for module call-backs */
    session s;          /* the current session */
    jpacket p;          /* the current jpacket */

    /* continue looping while there are still packets on the message port */
    while(1)
    {
        /* get a packet from the message port */
        q = (spacket)pth_msgport_get(mp);

        /* if there are no more packets, jump out of the loop */
        if(q == NULL)
            break;

        /* debug message */
        log_debug(ZONE,"PROCESS %X type %d for session %X",mp,q->type,q->s);

        /* local pointers */
        s = q->s;
        p = q->p;

        /* reinforce association between session and worker */
        s->worker = mp;

        /* handle packet according to type */
        switch(q->type)
        {
            /* start the session */
        case SPACKET_START:

            /* get the list of module callbacks for sessin start up */
            master = js_mapi_master(e_SESSION);

            /* let the modules go to it */
            js_mapi_call(e_SESSION, master->l, NULL, s->u, s, 0);

            /* log the start time of the session */
            s->started = time(NULL);
            break;

            /* outgoing packets from the session */
        case SPACKET_FROM:

            /* if this session is dead */
            if(s->exit_flag)
            {
                /* send the packet into oblivion */
                xmlnode_free(p->x);
                break;
            }

            /* at least we must have a valid packet */
            if(p->type == JPACKET_UNKNOWN)
            {
                /* if not,s send an error to the session */
                jutil_error(p->x,TERROR_BAD);
                jpacket_reset(p);
                js_session_to(s,p);
                break;
            }

            /* debug message */
            log_debug(ZONE,"THREAD:SESSION:FROM received a message!");

            /* increment packet out count */
            s->c_out++;

            /* make sure we have our from set correctly for outgoing packets */
            if(jid_cmp(p->from,s->uid) != 0 && jid_cmp(p->from,s->id) != 0)
            {
                /* nope, fix it */
                xmlnode_put_attrib(p->x,"from",jid_full(s->id));
                q->p->from = jid_new(p->p,jid_full(s->id));
            }

            /* let the modules have their heyday */
            if(js_mapi_call(es_OUT, s->m_out, p, s->u, s, jpacket_subtype(p)))
                break;

            /* no module handled it, so make sure there's a to attribute */
            if(p->to == NULL)
            {
                /* nope, make one based on the from attribute */
                xmlnode_put_attrib(p->x,"to",p->from->server);
                p->to = jid_new(p->p,p->from->server);
            }

            /* pass these to the general delivery function */
            js_deliver(p);

            break;

        case SPACKET_TO: /* incoming packets for the session */

            /* if this session is dead... */
            if(s->exit_flag)
            {
                /* ... and the packet is a message */
                if(p->type == JPACKET_MESSAGE)

                    /* deliver it */
                    js_deliver(p);

                else /* otherwise send it to oblivion */
                    xmlnode_free(p->x);
                break;

            }

            /* debug message */
            log_debug(ZONE,"THREAD:SESSION:TO received data from %s!",jid_full(p->from));

            /* increment packet in count */
            s->c_in++;

            /* let the modules have their heyday */
            if(js_mapi_call(es_IN, s->m_in, p, s->u, s, jpacket_subtype(p)))
                break;

            /* we need to check again, s->exit_flag *could* have changed within the modules at some point */
            if(s->exit_flag)
            {
                /* deliver that packet if it was a message, and sk'daddle */
                if(p->type == JPACKET_MESSAGE)
                    js_deliver(p);
                else
                    xmlnode_free(p->x);
                break;
            }

            /* deliver outgoing for this session to the onSend event passed when this session was created */
            (s->send)(s, p, s->arg);

            break;

        case SPACKET_END: /* buh-bye */

            /* debug message */
            log_debug(ZONE,"THREAD:SESSION exiting");

            /* decrement the user's session count */
            s->u->scount--;

            /* make sure the service knows the session is gone */
            (s->send)(s, NULL, s->arg);

            /* let the modules have their heyday */
            js_mapi_call(es_END, s->m_end, NULL, s->u, s, 0);

            /* let the user struct go  */
            s->u->ref--;

            /* free the session's presence state */
            xmlnode_free(s->presence);

            /* free the session's memory pool */
            pool_free(s->p);
            s = NULL;
            break;

        default:
        }

        /* disallusion the session and worker */
        if(s != NULL)
            s->worker = NULL;
    }
}

/*
 *  function_name -- entry point for session threads
 *  
 *  Sleep until an spacket arrives on the message port, then
 *  call js_session_process to deal with it. Repeat. The thread
 *  dies when finishes processing a packet and the pool of idle
 *  threads is full. This lets the server free up resouces if
 *  the load spikes and then dies off.
 *
 *  parameters
 *  	arg -- the worker thread
 *
 */
void *js_worker_main(void *arg)
{
    thread t = (thread)arg;                         /* cast arg into a proper thread */
    pth_msgport_t mp = (pth_msgport_t)(t->data);    /* the thread's message port */
    pth_event_t mpevt;                              /* an event ring to wait for - ie EVENT_MSG */
    int i;                                          /* index for traversing the idle thread pool */

    /* debug message */
    log_debug(ZONE,"THREAD:WORKER %X starting",mp);

    /* create an event ring for receiving messges */
    mpevt = pth_event(PTH_EVENT_MSG,mp);

    /* loop */
    while(1)
    {

        /* debug: note that we're waiting for a message */
        log_debug(ZONE,"WORKER(%X)->pth",mp);

        /* wait for a message on the port */
        pth_wait(mpevt);

        /* debug: note that we found one */
        log_debug(ZONE,"pth->WORKER(%X)",mp);

        /* take us out of the waiting pool */
        for(i=0;i<SESSION_WAITERS; i++)
            if(swaiters[i] == mp)
                swaiters[i] = NULL;

        /* process the waiting packets */
        js_session_process(mp);

        /* scan the waiting pool */
        for(i=0;i<SESSION_WAITERS && swaiters[i] != NULL; i++);

        /* no room for us, die */
        if(i+1 == SESSION_WAITERS)
            break;

        /* debug: note that we're going back to the waiting pool */
        log_debug(ZONE,"swaiters[%d] is now %X",i,mp);

        /* go back to the pool */
        swaiters[i] = mp;

    }

    /* debug: note that the thread is dying */
    log_debug(ZONE,"THREAD:WORKER %X exiting",mp);

    /* free all memory associated with the thread */
    pool_free(t->p);
    pth_event_free(mpevt,PTH_FREE_ALL);
    pth_msgport_destroy(mp);

    return NULL;
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

/*
 *  js_session_to -- send an incomming packet to the session
 *  
 *  This is a wrapper for js_packet
 *
 *  parameters
 *  	s -- the session to send to
 *      p -- the packet to send
 *
 */
void js_session_to(session s, jpacket p)
{
    /* forward the call to spacket, with the correct packet type */
    js_spacket(SPACKET_TO,s,p);
}

/*
 *  js_session_from -- route an outgoing packet from the session
 *  
 *  This is a wrapper for js_packet
 *
 *  parameters
 *  	s -- the session sending the packet
 *      p -- the packet to send
 *
 */
void js_session_from(session s, jpacket p)
{
    /* forward the call to spacket, with the correct packet type */
    js_spacket(SPACKET_FROM,s,p);
}

