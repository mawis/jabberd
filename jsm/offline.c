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
 *  offline.c -- thread that handles data for other packets,
 *               which might be for offline or unknown users
 *
 */

#include "jsm.h"

/*
 *  js_offline_main -- entry point for the offline thread
 *  
 *  Long_description
 *
 *  parameters
 *  	arg -- not used
 *
 */
void *js_offline_main(void *arg)
{
    pth_event_t ev;		/* event ring for retreiving messages */
    pth_msgport_t mp;	/* message port for sending messages to the thread */
    jpq q;				/* ??? */
    mmaster ml;			/* list of call backs for offline phase */
    udata user;			/* user data */

    /* debug message */
    log_debug(ZONE,"THREAD:OFFLINE starting");

    /* create the message port */
    mp = pth_msgport_create("js_offline");

    /* create an event ring for messages on the port */
    ev = pth_event(PTH_EVENT_MSG,mp);

    /* get our offline phase master list */
    ml = js_mapi_master(e_OFFLINE);

    /* infinite loop */
    while(1)
    {
        /* wait for a message */
        pth_wait(ev);

        /* get the packet from the message port */
        while((q = (jpq)pth_msgport_get(mp)) != NULL)
        {
            /* performace hack, don't lookup the udata again */
            user = (udata)q->p->aux1;

            /* debug message */
            log_debug(ZONE,"THREAD:OFFLINE received %s's packet: %s",user->user,xmlnode2str(q->p->x));

            /* let the modules handle the packet */
            if(!js_mapi_call(e_OFFLINE, ml->l, q->p, user, NULL, q->p->subtype))
                js_bounce(q->p->x,TERROR_UNAVAIL);

            /* it can be cleaned up now */
            user->ref--;

        }
    }

    /* shouldn't end up here, but just in case */
    pth_event_free(ev,PTH_FREE_ALL);
    pth_msgport_destroy(mp);
}


