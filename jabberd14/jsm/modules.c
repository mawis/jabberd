/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "License").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the License.  You
 * may obtain a copy of the License at http://www.jabber.com/license/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2000 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * modules.c - jsm module API
 * --------------------------------------------------------------------------*/

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
    mlist newl, curl;

    if(c == NULL || si == NULL || e >= e_LAST) return;

    /* create a new mlist record for the call back */
    newl = pmalloc(si->p, sizeof(_mlist));
    newl->c = c;
    newl->arg = arg;
    newl->mask = 0x00;
    newl->next = NULL;

    /* append */
    if(si->events[e] == NULL)
    {
        si->events[e] = newl;
    }else{
        for(curl = si->events[e]; curl->next != NULL; curl = curl->next); /* spin to end of list */
        curl->next = newl;
    }
    log_debug(ZONE,"mapi_register %d %X",e,newl);
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
    mlist newl, curl;

    if(c == NULL || s == NULL || e >= es_LAST) return;

    /* create item for the call list */
    newl = pmalloco(s->p, sizeof(_mlist));
    newl->c = c;
    newl->arg = arg;
    newl->mask = 0x00;
    newl->next = NULL;

    /* append */
    if(s->events[e] == NULL)
    {
        s->events[e] = newl;
    }else{
        for(curl = s->events[e]; curl->next != NULL; curl = curl->next); /* spin to end of list */
        curl->next = newl;
    }

    log_debug(ZONE,"mapi_register_session %d %X",e,newl);
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
log_debug(ZONE,"MAPI %X",l);
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
            ;
        }
    }

    log_debug(ZONE,"mapi_call returning unhandled");

    /* if we got here, no module handled the packet */
    return 0;
}

