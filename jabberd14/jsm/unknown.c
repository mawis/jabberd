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
 *  unknown.c -- thread that handles packets for unknown users
 *
 */

#include "jsm.h"

/*
 *  js_unknown_main -- entry point for the unknown thread
 *  
 *  parameters
 *  	arg -- unused
 */
void *js_unknown_main(void *arg)
{
    pth_event_t ev;		/* event ring for receiving messages */
    pth_msgport_t mp;	/* message port for recieving messages */
    jpq q;				/* packet to handle */
    mmaster ml;			/* list of call-backs for the unknown phase */

    /* debug message */
    log_debug(ZONE,"THREAD:UNKNOWN starting");

    /* create the event ring and message port */
    mp = pth_msgport_create("js_unknown");
    ev = pth_event(PTH_EVENT_MSG,mp);

    /* get our offline phase master list */
    ml = js_mapi_master(P_UNKNOWN);

    /* infinite loop */
    while(1)
    {
        /* wait for a message */
        pth_wait(ev);

        /* retreive and process packets from the port */
        while((q = (jpq)pth_msgport_get(mp)) != NULL)
        {
            /* debug message */
            log_debug(ZONE,"THREAD:UNKNOWN received packet: %s",xmlnode2str(q->p->x));

            /* let the modules handle the packet; if it's not handled... */
            if(!js_mapi_call(P_UNKNOWN, ml->l, q->p, NULL, NULL, q->p->subtype))

                /* bounce it with an error */
                js_bounce(q->p->x,TERROR_NOTFOUND);

        }
    }

    /* just in case, free the event ring and the port */
    pth_event_free(ev,PTH_FREE_ALL);
    pth_msgport_destroy(mp);

}


