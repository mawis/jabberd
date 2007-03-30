/*
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2007 Matthias Wimmer
 *
 * This file is part of jabberd14.
 *
 * This software is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

/**
 * @file heartbeat.cc
 * @brief functions used to register other functions to be called regularily
 */
#include "jabberd.h"

/** private heartbeat ring struct */
typedef struct beat_struct {
    beathandler f;
    void *arg;
    int freq;
    int last;
    pool p;
    struct beat_struct *prev;
    struct beat_struct *next;
} *beat, _beat;

/** master hook for the ring */
beat heartbeat__ring = NULL;

/**
 * this thread continuously checks if a function, that is registered to be called regularly using register_beat() has to be called again
 *
 * @param arg unused/ignored
 */
void *heartbeat(void *arg) {
    beat b, b2;
    result r;

    while(1) {
        pth_sleep(1);
        if(heartbeat__ring==NULL) break;

	/* run through the ring */
	for(b = heartbeat__ring->next; b != heartbeat__ring; b = b->next)
	{
	    /* beats can fire on a frequency, just keep a counter */
	    if(b->last++ == b->freq)
	    {
	        b->last = 0;
	        r = (b->f)(b->arg);

	        if(r == r_UNREG)
	        { /* this beat doesn't want to be fired anymore, unlink and free */
	            b2 = b->prev;
		    b->prev->next = b->next;
		    b->next->prev = b->prev;
		    pool_free(b->p);
		    b = b2; /* reset b to accomodate the for loop */
	        }
	    }
	}
    }
    return NULL;
}

/**
 * allocate memory for a new heartbeat
 */
beat _new_beat(void) {
    beat newb;
    pool p;

    p = pool_new();
    newb = static_cast<beat>(pmalloco(p, sizeof(_beat)));
    newb->p = p;

    return newb;
}

/**
 * register a function to receive heartbeats
 */
void register_beat(int freq, beathandler f, void *arg) {
    beat newb;

    if(freq <= 0 || f == NULL || heartbeat__ring == NULL) return; /* uhh, probbably don't want to allow negative heartbeats, since the counter will count infinitly to a core */

    /* setup the new beat */
    newb = _new_beat();
    newb->f = f;
    newb->arg = arg;
    newb->freq = freq;
    newb->last = 0;

    /* insert into global ring */
    newb->next = heartbeat__ring->next;
    heartbeat__ring->next = newb;
    newb->prev = heartbeat__ring;
    newb->next->prev = newb;
}

/**
 * start up the heartbeat
 */
void heartbeat_birth(void)
{
    /* init the ring */
    heartbeat__ring = _new_beat();
    heartbeat__ring->next = heartbeat__ring->prev = heartbeat__ring;

    /* start the thread */
    pth_spawn(PTH_ATTR_DEFAULT, heartbeat, NULL);
}

/**
 * stop calling hearbeat functions
 */
void heartbeat_death(void) {
    beat cur;
    while(heartbeat__ring!=NULL)
    {
       cur=heartbeat__ring;
       if(heartbeat__ring->next==heartbeat__ring) 
       {
           heartbeat__ring=NULL;
       }
       else
       {
           if(heartbeat__ring->next!=NULL)
               heartbeat__ring->next->prev=heartbeat__ring->prev;
           if(heartbeat__ring->prev!=NULL) 
               heartbeat__ring->prev->next=heartbeat__ring->next;
           heartbeat__ring=heartbeat__ring->next;
       }
       pool_free(cur->p);
    }
}
