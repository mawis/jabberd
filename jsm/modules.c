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
 *  js_mapi_master -- retreive a MAPI master list 
 *  
 *  Fetches a master list which contains the module call-backs
 *  for a particular phase of server operation
 *
 *  parameters
 *  	p -- the phase. values are #defined in jsm.hs
 *
 *  returns
 *      a pointer to the master list for phase p 
 */
mmaster js_mapi_master(mphase p)
{
    static mmaster master = NULL;	/* the master list for all phases */
    mmaster cur;					/* use to iterate over master */

    /* debug message */
    log_debug(ZONE,"mapi_master %d",p);

    /* find the master list for phase p */
    for(cur = master; cur != NULL; cur = cur->next)
        if(cur->p == p) break;

    /* if it wasn't found, an empty one create one */
    if(cur == NULL)
    {
        cur = malloc(sizeof(_mmaster));
        cur->p = p;
        cur->l = NULL;
        cur->next = master;
        master = cur;
    }

    return cur;
}

/*
 *  js_mapi_master -- let a module register a new call for this phase 
 *  
 *  Takes a function pointer and argument and stores them in the
 *  call back list for the phase p
 *
 *  parameters
 *  	p -- the phase. values are #defined in jsm.hs
 *      c -- pointer to an mcall function
 *      arg -- an argument to pass to c when it is called
 *
 */
void js_mapi_register(mphase p, mcall c, void *arg)
{
    mlist newl, curl;	/* items in a call-back list */
    mmaster master;		/* the master list for the phase */

    /* ignore illegal calls */
    if(c == NULL) return;

    /* debug message */
    log_debug(ZONE,"mapi_register %d",p);

    /* create a new mlist record for the call back */
    newl = malloc(sizeof(_mlist));
    newl->c = c;
    newl->arg = arg;
    newl->mask = 0x00;
    newl->next = NULL;

    /* fetch the master list for this phase */
    master = js_mapi_master(p);

    /* if there are no other list items */
    if(master->l == NULL)
    {
        /* add the new list item to the head */
        master->l = newl;

    }else{

        /* append to end of call list */
        for(curl = master->l; curl->next != NULL; curl = curl->next);
        curl->next = newl;

    }
}

/*
 *  js_mapi_session -- let a module register a new call for this session phase
 *  
 *  This is like js_mapi_register except that the call only
 *  applies to the specified session.
 *
 *  parameters
 *  	p -- the phase. values are #defined in jsm.h
 *		s -- the session to register the call with
 *      c -- pointer to an mcall function
 *      arg -- an argument to pass to c when it is called
 *
 */
void js_mapi_session(mphase p, session s, mcall c, void *arg)
{
    mlist newl, curl, *curs; /* FIXME: why the double indirection here? */

    /* ignore illegal calls */
    if(c == NULL || s == NULL) return;

    /* debug message */
    log_debug(ZONE,"mapi_register_session %d",p);

    /* create item for the call list */
    newl = pmalloc(s->p, sizeof(_mlist));
    newl->c = c;
    newl->arg = arg;
    newl->mask = 0x00;
    newl->next = NULL;

    /* save the new list item in the master list for this phase */
    switch(p)
    {
    case PS_IN:
        curs = &(s->m_in);
        break;
    case PS_OUT:
        curs = &(s->m_out);
        break;
    case PS_END:
        curs = &(s->m_end);
        break;
    default:
        /* dork */
        return;
    }

    /* is the list empty? */
    if(*curs == NULL)
    {
        /* yes, store it at the head of the list */
        *curs = newl;

    }else{

        /* append to end of call list */
        for(curl = *curs; curl->next != NULL; curl = curl->next);
        curl->next = newl;

    }
}

/*
 *  js_mapi_call -- call all the module call-backs for a phase
 *  
 *  parameters
 *  	phase -- the phase. values are #defined in jsm.h
 *		l -- the list of functions to call
 *      packet -- the packet being processed, may be NULL
 *      user -- the user data for the current session
 *      s -- the session
 *      variant -- the variant of the phase (used for registration)
 *
 */
int js_mapi_call(mphase phase, mlist l, jpacket packet, udata user, session s, int variant)
{
    _mapi m;		/* mapi structure to be passed to the call back */

    /* ignore illegal calls  */
    if(l == NULL) return 0;

    /* debug message */
    log_debug(ZONE,"mapi_call %d",phase);

    /* fill in the mapi structure */
    m.phase = phase;
    m.packet = packet;
    m.user = user;
    m.s = s;
    m.variant = variant;

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

    /* if we got here, no module handled the packet */
    return 0;
}

