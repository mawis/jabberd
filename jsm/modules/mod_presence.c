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

/* util to check for valid roster items */
int mod_presence_roster(udata user, jid id)
{
    xmlnode roster, item;
    int ret = 0;

    /* get roster */
    roster = xdb_get(user->si->xc, user->id->server, user->id, NS_ROSTER);

    item = jid_nodescan(id, roster);

    if(item != NULL)
        ret = 1;

    xmlnode_free(roster);
    return ret;
}

/* filter the incoming presence to this session */
mreturn mod_presence_in(mapi m, void *arg)
{
    xmlnode pres;

    if(m->packet->type != JPACKET_PRESENCE) return M_IGNORE;

    log_debug("mod_presence","incoming filter for %s",jid_full(m->s->id));

    if(jpacket_subtype(m->packet) == JPACKET__PROBE)
    { /* reply with our presence */
        if(m->s->presence == NULL)
        {
            log_debug("mod_presence","probe from %s and no presence to return",jid_full(m->packet->from));
        }else if(mod_presence_roster(m->user, m->packet->from) || jid_cmp(m->packet->from,m->s->uid) == 0)
        {
            log_debug("mod_presence","got a probe, responding to %s",jid_full(m->packet->from));
            pres = xmlnode_dup(m->s->presence);
            xmlnode_put_attrib(pres,"to",jid_full(m->packet->from));
            js_session_from(m->s,jpacket_new(pres));
        }else{
            log_debug("mod_presence","%s attempted to probe and is not on the roster",jid_full(m->packet->from));
        }
        xmlnode_free(m->packet->x);
        return M_HANDLED;
    }

    if(jid_cmp(m->packet->from,m->s->id) == 0)
    { /* this is our presence, don't send to ourselves */
        xmlnode_free(m->packet->x);
        return M_HANDLED;
    }

    return M_PASS;
}

mreturn mod_presence_out(mapi m, void *arg)
{
    xmlnode pres, pnew, roster, cur, delay;
    jid id;
    session top;
    int from, to, pri, oldpri;

    if(m->packet->type != JPACKET_PRESENCE) return M_IGNORE;

    if(m->packet->to != NULL) return M_PASS;

    log_debug("mod_presence","new presence from %s of  %s",jid_full(m->s->id),xmlnode2str(m->packet->x));

    /* pre-existing conditions (no, we are not an insurance company) */
    top = js_session_primary(m->user);
    oldpri = m->s->priority;

    /* our new presence */
    xmlnode_free(m->s->presence);
    m->s->presence = pres = xmlnode_dup(m->packet->x);
    m->s->priority = pri = jutil_priority(m->packet->x);

    /* send to self */
    pnew = xmlnode_dup(pres);
    xmlnode_put_attrib(pnew,"to",jid_full(m->s->uid));
    js_session_from(m->s,jpacket_new(pnew));

    /* curious about self */
    if(top == NULL)
    {
        pnew = jutil_presnew(JPACKET__PROBE,jid_full(m->s->uid),NULL);
        xmlnode_put_attrib(pnew,"from",jid_full(m->s->uid));
        js_session_from(m->s, jpacket_new(pnew));
    }else if(oldpri < 0){
        while((pnew = ppdb_get(m->user->p_cache,m->s->uid)) != NULL)
            js_session_to(m->s,jpacket_new(xmlnode_dup(pnew)));
    }

    /* push to roster subscriptions */
    roster = xdb_get(m->si->xc, m->user->id->server, m->user->id, NS_ROSTER);
    for(cur = xmlnode_get_firstchild(roster); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        id = jid_new(m->packet->p,xmlnode_get_attrib(cur,"jid"));
        if(id == NULL) continue;

        log_debug("mod_presence","roster item %s s10n=%s",jid_full(id),xmlnode_get_attrib(cur,"subscription"));

        /* vars */
        to = from = 0;
        if(j_strcmp(xmlnode_get_attrib(cur,"subscription"),"to") == 0)
            to = 1;
        if(j_strcmp(xmlnode_get_attrib(cur,"subscription"),"from") == 0)
            from = 1;
        if(j_strcmp(xmlnode_get_attrib(cur,"subscription"),"both") == 0)
            to = from = 1;

        /* curiosity phase */
        if(to && pri >= 0)
        {
            if(top == NULL)
            { /* there's nothing cached, send probes */
                log_debug("mod_presence","we're new here, probe them");
                pnew = jutil_presnew(JPACKET__PROBE,jid_full(id),NULL);
                xmlnode_put_attrib(pnew,"from",jid_full(m->s->uid));
                js_session_from(m->s, jpacket_new(pnew));
            }else if(oldpri < 0){ /* this connection now wants to know about others' presence */
                /* dump from cache */
                log_debug("mod_presence","dumping them from the cache");
                while((pnew = ppdb_get(m->user->p_cache,id)) != NULL)
                    js_session_to(m->s,jpacket_new(xmlnode_dup(pnew)));
            }
        }

        /* delivery phase */
        if(from && (top == NULL || !to || ppdb_primary(m->user->p_cache,id) != NULL))
        { /* follow that?  helluva if, eh?  it used to be a bunch of em, but why not obfuscate it into one :)
                   * from: ok, first, they have to be subscribed to us
                   * top == NULL: always send if we don't have anything cached (since we're just becoming available now)
                   * !to: always send if we don't know anything about them
                   * ppdb != NULL: if we should know their presence, and they are available, forward
                   */
            log_debug("mod_presence","delivering to them");
            pnew = xmlnode_dup(pres);
            xmlnode_put_attrib(pnew,"to",jid_full(id));
            js_session_from(m->s,jpacket_new(pnew));
        }

    }

    /* invalidate the cache */
    if(js_session_primary(m->user) == NULL && m->user->p_cache != NULL)
    {
        ppdb_free(m->user->p_cache);
        m->user->p_cache = NULL;
    }

    /* stamp the sessions presence */
    delay = xmlnode_insert_tag(pres,"x");
    xmlnode_put_attrib(delay,"xmlns",NS_DELAY);
    xmlnode_put_attrib(delay,"from",jid_full(m->s->id));
    xmlnode_put_attrib(delay,"stamp",jutil_timestamp());

    xmlnode_free(m->packet->x);
    xmlnode_free(roster);
    return M_HANDLED;
}

mreturn mod_presence_avails(mapi m, void *arg)
{
    jid *avails = (jid *)arg;
    jid curr;

    if(m->packet->type != JPACKET_PRESENCE) return M_IGNORE;

    if(m->packet->to == NULL) return M_PASS;

    log_debug("mod_presence","avail tracker");

    /* add to the list, or init it */
    if(jpacket_subtype(m->packet) == JPACKET__AVAILABLE && jid_append(*avails, m->packet->to) == NULL)
        *avails = jid_new(m->s->p,jid_full(m->packet->to));

    /* remove from the list */
    if(jpacket_subtype(m->packet) == JPACKET__UNAVAILABLE)
    {
        if(jid_cmp(m->packet->to,*avails) == 0)
        {
            curr = *avails;
            *avails = curr->next;
        }else{
            for(curr = *avails;curr != NULL && jid_cmp(curr->next,m->packet->to) != 0;curr = curr->next);
            if(curr != NULL && curr->next != NULL)
                curr->next = curr->next->next;
        }
    }

    return M_PASS;
}

mreturn mod_presence_avails_end(mapi m, void *arg)
{
    jid *avails = (jid *)arg;
    jid curr;
    xmlnode pres;

    log_debug("mod_presence","avail tracker guarantee");

    /* loop through avails list, sending each the current presence (which the server set to unavail) */
    xmlnode_put_attrib(m->s->presence, "from",jid_full(m->s->id));
    for(curr = *avails;curr != NULL;curr = curr->next)
    {
        pres = xmlnode_dup(m->s->presence);
        xmlnode_put_attrib(pres, "to",jid_full(curr));
        js_deliver(m->si,jpacket_new(pres));
    }

    return M_PASS;
}

mreturn mod_presence_session(mapi m, void *arg)
{
    jid *avails;

    avails = pmalloc(m->s->p, sizeof(jid *));
    *avails = NULL;

    js_mapi_session(es_IN, m->s, mod_presence_in, NULL);
    js_mapi_session(es_OUT, m->s, mod_presence_avails, avails); /* must come first, it passes, _out handles */
    js_mapi_session(es_OUT, m->s, mod_presence_out, NULL);
    js_mapi_session(es_END, m->s, mod_presence_avails_end, avails);

    return M_PASS;
}

mreturn mod_presence_deliver(mapi m, void *arg)
{
    session cur;

    if(m->packet->type != JPACKET_PRESENCE) return M_IGNORE;

    log_debug("mod_presence","deliver phase");

    /* only if we HAVE a user, and it was sent to ONLY the user@server, and there is at least one session available */
    if(m->user != NULL && m->packet->to->resource == NULL && js_session_primary(m->user) != NULL)
    {
        log_debug("mod_presence","broadcasting to %s caching in %X",m->user->user,m->user->p_cache);

        /* broadcast */
        for(cur = m->user->sessions; cur != NULL; cur = cur->next)
        {
            if(cur->priority < 0) continue;
            log_debug(ZONE,"!!1 cur %X cur->next %X\n",cur,cur->next);
            js_session_to(cur, jpacket_new(xmlnode_dup(m->packet->x)));
            log_debug(ZONE,"!!2 cur %X cur->next %X\n",cur,cur->next);
        }

        if(jpacket_subtype(m->packet) != JPACKET__PROBE)
        { /* probes get handled by the offline thread as well, rest get cached */
            jutil_delay(m->packet->x,"received");
            m->user->p_cache = ppdb_insert(m->user->p_cache, m->packet->from, m->packet->x);
            xmlnode_free(m->packet->x);
            return M_HANDLED;
        }
    }

    return M_PASS;
}

void mod_presence(jsmi si)
{
    log_debug("mod_presence","init");
    js_mapi_register(si,e_DELIVER, mod_presence_deliver, NULL);
    js_mapi_register(si,e_SESSION, mod_presence_session, NULL);
}

