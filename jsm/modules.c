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
 *  modules.c -- implements the module API
 *
 */

#include "jsm.h"

/*
 *  js_mapi_register -- let a module register a new call for this phase 
 *  
 *  Takes a function pointer and argument and stores them in the
 *  call back list for the event e
 *
 *  parameters
 *  	e -- the event type, values are #defined in jsm.hs
 *  	si -- session instance
 *      c -- pointer to an mcall function
 *      arg -- an argument to pass to c when it is called
 *
 */
void js_mapi_register(jsmi si, event e, mcall c, void *arg)
{
    mlist newl;

    if(c == NULL || si == NULL || e >= e_LAST) return;

    log_debug(ZONE,"mapi_register %d",e);

    /* create a new mlist record for the call back */
    newl = pmalloc(si->p, sizeof(_mlist));
    newl->c = c;
    newl->arg = arg;
    newl->mask = 0x00;
    newl->next = si->events[e];
    si->events[e] = newl;
}

/*
 *  js_mapi_session -- let a module register a new call for this session phase
 *  
 *  This is like js_mapi_register except that the call only
 *  applies to the specified session.
 *
 *  parameters
 *  	e -- the event type, values are #defined in jsm.hs
 *      s -- the session to register the call with
 *      c -- pointer to an mcall function
 *      arg -- an argument to pass to c when it is called
 *
 */
void js_mapi_session(event e, session s, mcall c, void *arg)
{
    mlist newl;

    if(c == NULL || s == NULL || e >= es_LAST) return;

    log_debug(ZONE,"mapi_register_session %d",e);

    /* create item for the call list */
    newl = pmalloc(s->p, sizeof(_mlist));
    newl->c = c;
    newl->arg = arg;
    newl->mask = 0x00;
    newl->next = s->events[e];
    s->events[e] = newl;
}

/*
 *  js_mapi_call -- call all the module call-backs for a phase
 *
 *  parameters
 *  	e -- event type, values are #defined in jsm.h
 *      packet -- the packet being processed, may be NULL
 *      user -- the user data for the current session
 *      s -- the session
 *
 */
int js_mapi_call(jsmi si, event e, jpacket packet, udata user, session s)
{
    mlist l;
    _mapi m;		/* mapi structure to be passed to the call back */

    log_debug(ZONE,"mapi_call %d",e);

    /* this is a session event */
    if(si == NULL && s != NULL)
    {
        si = s->si;
        l = s->events[e];
    }else{
        l = si->events[e];
    }

    /* fill in the mapi structure */
    m.si = si;
    m.e = e;
    m.packet = packet;
    m.user = user;
    m.s = s;

    /* traverse the list of call backs */
    for(;l != NULL; l = l->next)
    {
        /* skip call-back if the packet type mask matches */
        if(packet != NULL && (packet->type & l->mask) == packet->type) continue;

        /* call the function and handle the result */
        switch((*(l->c))(&m, l->arg))
        {
        /* this module is ignoring this packet->type */
        case M_IGNORE:
            /* add the packet type to the mask */
            l->mask |= packet->type;
            break;
        /* this module handled the packet */
        case M_HANDLED:
            return 1;
        default:
        }
    }

    log_debug(ZONE,"mapi_call returning unhandled");

    /* if we got here, no module handled the packet */
    return 0;
}

