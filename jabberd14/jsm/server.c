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
 *  server.c -- thread that handles messages/packets intended for the server:
 *				administration, public IQ (agents, etc)
 */

#include "jserver.h"

/*
 *  js_server_main -- entry point for the server thread
 *  
 *  parameters
 *  	arg -- not used
 *
 */
void *js_server_main(void *arg)
{
    pth_event_t ev;		/* event ring for receiving messages */
    pth_msgport_t mp;	/* message port for receiving messages */
    jpq q;				/* a jabber packet */
    mmaster ml;			/* list of module call-backs for the server phase */

    /* debug message */
    log_debug(ZONE,"THREAD:SERVER starting");

    /* create the message port and event ring */
    mp = pth_msgport_create("js_server");
    ev = pth_event(PTH_EVENT_MSG,mp);

    /* get our server phase master list */
    ml = js_mapi_master(P_SERVER);

    /* infinite loop */
    while(1)
    {
        /* wait for a message */
        pth_wait(ev);

        /* get a packet from the message port */
        while((q = (jpq)pth_msgport_get(mp)) != NULL)
        {
            /* debug message */
            log_debug(ZONE,"THREAD:SERVER received a packet: %s",xmlnode2str(q->p->x));

            /* let the modules have a go at the packet; if nobody handles it... */
            if(!js_mapi_call(P_SERVER, ml->l, q->p, NULL, NULL, q->p->subtype))

                /* ...bounce the packet with an error */
                js_bounce(q->p->x,TERROR_NOTFOUND);

        }
    }

    /* shouldn't arrive here, but clean up, just in case */
    pth_event_free(ev,PTH_FREE_ALL);
    pth_msgport_destroy(mp);

}


