/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "JOSL").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the JOSL. You
 * may obtain a copy of the JOSL at http://www.jabber.org/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the JOSL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the JOSL
 * for the specific language governing rights and limitations under the
 * JOSL.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 or later (the "GPL"), in which case
 * the provisions of the GPL are applicable instead of those above.  If you
 * wish to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the JOSL,
 * indicate your decision by deleting the provisions above and replace them
 * with the notice and other provisions required by the GPL.  If you do not
 * delete the provisions above, a recipient may use your version of this file
 * under either the JOSL or the GPL. 
 * 
 * --------------------------------------------------------------------------*/

/**
 * @file sessions.c
 * @brief handle messages to and from user sessions
 */

#include "jsm.h"

/* forward declarations */
void _js_session_start(void *arg);
void _js_session_to(void *arg);
void _js_session_from(void *arg);
void _js_session_end(void *arg);

/**
 * deliver a packet to the client connection manager responsible for the session
 *
 * The packet is wrapped inside a <route/> element and routed to
 * the client connection manager, that handles the connection for the
 * sepcified session. If the xmlnode in is NULL, a <route type='error'/>
 * stanza is sent to the client connection manager, signalling that the
 * session is not valid anymore.
 *
 * @param s the session to which the packet should be routed to
 * @param in the stanza that should be routed to the c2s for the session
 */
void js_session_route(session s, xmlnode in)
{
    /* NULL means this is an error from the session ending */
    if(in == NULL)
    {
         in = xmlnode_new_tag("route");
         xmlnode_put_attrib(in, "type", "error");
         xmlnode_put_attrib(in, "error", "Disconnected");
    }else{
        in = xmlnode_wrap(in,"route");
    }

    xmlnode_put_attrib(in, "from", jid_full(s->route));
    xmlnode_put_attrib(in, "to", jid_full(s->sid));
    deliver(dpacket_new(in), s->si->i);
}

/**
 * create a new session, register the resource for it
 *
 * Sets up all the data associated with a new session, then
 * notify all modules that registered for e_SESSION about the newly created session
 *
 * @param si the session manager instance data
 * @param dp the packet we received from the c2s instance, that requested the new session
 * @return a pointer to the new session (NULL if input data is invalid)
 */
session js_session_new(jsmi si, dpacket dp) {
    pool p;         /* a memory pool for the session */
    session s, cur;      /* the session being created */
    int i;
    udata u;
    char routeres[10];

    /* screen out illegal calls */
    if(dp == NULL || dp->id->user == NULL || dp->id->resource == NULL || xmlnode_get_attrib(dp->x,"from") == NULL || (u = js_user(si,dp->id,NULL)) == NULL)
        return NULL;

    log_debug2(ZONE, LOGT_SESSION, "session_create %s",jid_full(dp->id));

    /* create session */
    p = pool_heap(2*1024);
    s = pmalloco(p, sizeof(struct session_struct));
    s->p = p;
    s->si = si;

    /* save authorative remote session id */
    s->sid = jid_new(p, xmlnode_get_attrib(dp->x,"from"));

    /* session identity */
    s->id = jid_new(p, jid_full(dp->id));
    s->route = jid_new(p, jid_full(dp->id));
    snprintf(routeres,9,"%X",s);
    jid_set(s->route, routeres, JID_RESOURCE);
    s->res = pstrdup(p, dp->id->resource);
    s->u = u;

    /* default settings */
    s->exit_flag = 0;
    s->roster = 0;
    s->priority = -129;
    s->presence = jutil_presnew(JPACKET__UNAVAILABLE,NULL,NULL);
    xmlnode_put_attrib(s->presence,"from",jid_full(s->id));
    s->c_in = s->c_out = 0;
    s->q = mtq_new(s->p);
    for(i = 0; i < es_LAST; i++)
        s->events[i] = NULL;

    /* remove any other session w/ this resource */
    for(cur = u->sessions; cur != NULL; cur = cur->next)
        if(j_strcmp(dp->id->resource, cur->res) == 0)
            js_session_end(cur, "Replaced by new connection");

    /* make sure we're linked with the user */
    s->next = s->u->sessions;
    s->u->sessions = s;
    s->u->scount++;

    /* start it */
    mtq_send(s->q, s->p, _js_session_start, (void *)s);

    return s;
}

/**
 * shut down the session
 *
 * This function gets called when the user disconnects or when the server shuts down.
 * It changes the user's presence to offline, cleans up the session data and notifies
 * all registered modules for the es_END event about the closed session
 *
 * @param s the session, that is closing
 * @param reason textual reason for the shutdown
 */
void js_session_end(session s, char *reason) {
    xmlnode x;      /* new presence data */
    session cur;    /* used to iterate over the user's session list
                       when removing the session from the list */

    /* ignore illegal calls */
    if(s == NULL || s->exit_flag == 1 || reason == NULL)
        return;

    /* log the reason the session ended */
    log_debug2(ZONE, LOGT_SESSION, "end %d '%s'",s,reason);

    /* flag the session to exit ASAP */
    s->exit_flag = 1;

    /* make sure we're not the primary session */
    s->priority = -129;

    /* if the last known presence was available, update it */
    if(s->presence != NULL && j_strcmp(xmlnode_get_attrib(s->presence, "type"), "unavailable") != 0) {

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
    if(s == s->u->sessions) {
        /* yup, just bump up the next session */
        s->u->sessions = s->next;
    } else {
        /* no, we have to traverse the list to find it */
        for(cur = s->u->sessions; cur->next != s; cur = cur->next);
        cur->next = s->next;
    }

    /* so it doesn't get freed */
    s->u->ref++;

    /* tell it to exit */
    mtq_send(s->q, s->p, _js_session_end, (void *)s);
}

/**
 * child that starts a session
 *
 * Calles all registered modules for the event e_SESSION and notifies them about the newly created session
 *
 * @param arg the newly created session
 */
void _js_session_start(void *arg)
{
    session s = (session)arg;

    /* let the modules go to it */
    js_mapi_call(s->si, e_SESSION, NULL, s->u, s);

    /* log the start time of the session */
    s->started = time(NULL);
}

/**
 * Child that handles packets we just received from the client connection manager from one of our users
 *
 * It is checked first if the packet is of a known type, if not it gets rejected.
 * For known packets it is first tried if one of the registered modules for es_OUT handles the packet,
 * iff none of the modules handles the packet, it is further passed to js_deliver().
 *
 * @param arg the packet we just received
 */
void _js_session_from(void *arg)
{
    jpacket p = (jpacket)arg;
    session s = (session)(p->aux1);
    jid uid;

    /* if this session is dead */
    if(s->exit_flag) {
        /* send the packet into oblivion */
        xmlnode_free(p->x);
        return;
    }

    /* at least we must have a valid packet */
    if(p->type == JPACKET_UNKNOWN) {
        /* send an error back */
        jutil_error_xmpp(p->x,XTERROR_BAD);
        jpacket_reset(p);
        js_session_to(s,p);
        return;
    }

    /* debug message */
    log_debug2(ZONE, LOGT_DELIVER, "THREAD:SESSION:FROM received a packet!");

    /* increment packet out count */
    s->c_out++;

    /* make sure we have our from set correctly for outgoing packets */
    if(jid_cmpx(p->from,s->id,JID_USER|JID_SERVER) != 0)
    {
        /* nope, fix it */
        xmlnode_put_attrib(p->x,"from",jid_full(s->id));
        p->from = jid_new(p->p,jid_full(s->id));
    }

    /* if you use to="yourself@yourhost" it's the same as not having a to, the modules use the NULL as a self-flag */
    uid = jid_user(s->id);
    if(jid_cmp(p->to,uid) == 0)
    {
        /* xmlnode_hide_attrib(p->x,"to"); */
        p->to = NULL;
    }

    /* let the modules have their heyday */
    if(js_mapi_call(NULL, es_OUT,  p, s->u, s))
        return;

    /* no module handled it, so restore the to attrib to us */
    if(p->to == NULL)
    {
        xmlnode_put_attrib(p->x,"to",jid_full(uid));
        p->to = jid_new(p->p,jid_full(uid));
    }

    /* pass these to the general delivery function */
    js_deliver(s->si, p);

}

/**
 * child that handles packets to a specified resource (session) of a user
 *
 * It is checked if the session the packet is addressed to has the exit_flag set,
 * if so it is sent back (?) to js_deliver(). If the exit_flag is not set
 * it is first tried if one of the registered callbacks for es_IN handles the
 * packet. Iff not the exit_flag is checked again (and probably the packet sent
 * back to js_deliver()) and if it is still not set, the packet is passed to
 * js_session_route() which delivers it to the c2s for sending it to the
 * connection related to the session.
 *
 * @param arg the packet
 */
void _js_session_to(void *arg)
{
    jpacket p = (jpacket)arg;
    session s = (session)(p->aux1);

    /* if this session is dead... */
    if(s->exit_flag) {
        /* ... and the packet is a message */
        if(p->type == JPACKET_MESSAGE)
            js_deliver(s->si, p);
        else /* otherwise send it to oblivion */
            xmlnode_free(p->x);
        return;
    }

    /* debug message */
    log_debug2(ZONE, LOGT_DELIVER, "THREAD:SESSION:TO received data from %s!",jid_full(p->from));

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

    /* deliver to listeners on session */
    js_session_route(s, p->x);
}

/**
 * child that cleans up a session
 *
 * Notify the responsible c2s instance about the closed session.
 * Call the modules that registered for the es_END event, to notify them about the closed session
 *
 * @param arg the session, that is closing
 */
void _js_session_end(void *arg)
{
    session s = (session)arg;

    /* debug message */
    log_debug2(ZONE, LOGT_SESSION, "THREAD:SESSION exiting");

    /* decrement the user's session count */
    s->u->scount--;

    /* make sure the service knows the session is gone */
    if(s->sid != NULL)
        js_session_route(s, NULL);

    /* let the modules have their heyday */
    js_mapi_call(NULL, es_END, NULL, s->u, s);

    /* let the user struct go  */
    s->u->ref--;

    /* free the session's presence state */
    xmlnode_free(s->presence);

    /* free the session's memory pool */
    pool_free(s->p);
}

/**
 * find the session for a given resource
 *
 * Given a user and a resource, find the corresponding session
 * if the user is logged in. Otherweise return NULL.
 *
 * @param user the user's udata record
 * @param res the resource to search for
 * @return a pointer to the session if the user is logged in, NULL if the user isn't logged in on this resource
 */
session js_session_get(udata user, char *res) {
    session cur;    /* session pointer */

    /* screen out illeagal calls */
    if(user == NULL || res == NULL)
        return NULL;

    /* find the session and return it*/
    for(cur = user->sessions; cur != NULL; cur = cur->next)
        if(j_strcmp(res, cur->res) == 0)
            return cur;

    /* find any matching resource that is a subset and return it */
    for(cur = user->sessions; cur != NULL; cur = cur->next)
        if(j_strncmp(res, cur->res, j_strlen(cur->res)) == 0)
            return cur;

    /* if we got this far, there is no session */
    return NULL;
}

/**
 * find the primary session for the user
 *
 * Scan through the user's sessions to find the session with the
 * highest priority and return a pointer to it.
 *
 * @param user the user to find the highest session for
 * @return pointer to the primary session if the user is logged in with at least priority 0, NULL if there is no active session with a priority of at least 0
 */
session js_session_primary(udata user) {
    session cur, top;

    /* ignore illegal calls, or users with no sessions */
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

    /* otherwise there's no active session */
    return NULL;
}

/**
 * handle packets addresses to a specific resource (session) of a user
 *
 * pass them to _js_session_to() ...
 *
 * @param s the session the packet is addressed to
 * @param p the packet
 */
void js_session_to(session s, jpacket p)
{
    /* XXX: Florian had on his server the case where mod_offline.c called this function
     * with p==NULL, I don't know how this could happen yet. I have to check further if
     * this is a bug that is remotly expoitable ... if NULL is passed as p, p->p in this
     * function will cause a segmentation violation!
     */
    if (s==NULL || p==NULL) {
	log_debug(ZONE, "logic error? js_session_to(%x, %x)", s, p);
	return;
    }

    /* queue the call to child, hide session in packet */
    p->aux1 = (void *)s;
    mtq_send(s->q, p->p, _js_session_to, (void *)p);
}

/**
 * handle normal stanzas received inside a <route/> stanza from
 * jabberd. These are packets we get from the client connection manager,
 * that are from one of our users.
 *
 * Pass them to _js_session_from() ...
 *
 * @param s the session of the user
 * @param p the received packet
 */
void js_session_from(session s, jpacket p)
{
    /* check the provided parameters */
    if (s==NULL || p==NULL) {
	log_debug(ZONE, "logic error? js_session_from(%x, %x)", s, p);
	return;
    }

    /* queue the call to child, hide session in packet */
    p->aux1 = (void *)s;
    mtq_send(s->q, p->p, _js_session_from, (void *)p);
}
