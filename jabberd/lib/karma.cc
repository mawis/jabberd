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
 * @file karma.cc
 * @brief implements bandwidth limits
 *
 * This is used by jabberd to limit the connection bandwidth on the receiving
 * side of TCP/IP connections.
 *
 * jabberd uses a "karma" based system to control socket io rate limits.
 * The more karma you have, the more you are allowed to write data to your
 * socket.
 *
 * You are allowed to write karma*100 bytes to your socket. In addition to your
 * karma, the server keeps track of how much data you have written lately.
 *
 * The only thing that will raise your karma is time. Karma is raised every
 * two seconds. In addition to raising your karma, it will lower your recent
 * "bytes out" count by karma*100 bytes.
 *
 * You are penalized for writing too much data to the socket at once. The lower
 * your karma is, the more this penalty has effect. If you have a negative
 * karma, the server will not read from your socket at all, until your karma
 * is positive again.
 *
 * If your recent "bytes sent" counter is greater than karma*100, your karma
 * is lowered, which will also lower the number of bytes the server will
 * read from you.
 *
 * Most of the karma values are configurable. The only values that cannot
 * be configured outside of karma.c, are the rate at which karma regenerates
 * (currently 2 seconds), and the karma*100 value. These two values are
 * defined in jabberdlib.h as KARMA_HEARTBEAT and as KARMA_READ_MAX(k).
 *
 * Values that can be changed outside of karma.c on a per-socket basis are:
 * current karma, current bytes_read, a max karma (you cannot have more than
 * this amount), an "init" value, for the first time init (normal karma
 * operation should never hit this value - sets to "restore" value), how much
 * karma is incremented/decremented, the "penalty" for dropping to zero
 * karma (usually a negative number, karma gets set to this value, when you
 * hit zero), the "restore" value for when your karma *raises* to zero (when
 * karma is negative and raises to zero, this value becomes the new karma).
 *
 * By default, these numbers start at: 5, 0, 10, -10, -5, and 5 respectivly.
 * Using these numbers a person with maximum karma (10), will be able to send
 * 1000 bytes every two seconds, without incuring any penalties. They would
 * also be able to send a burst of up to 5.5 KiB in two seconds, without
 * hitting zero karma. Once the user hits zero karma, they would only be
 * able to sustain a rate of about 1.5 KB every 10 seconds, until they wait
 * for their karma to raise to a more normal value.
 */

#include <jabberdlib.h>

/**
 * make a copy of a karma structure
 *
 * @param new_instance pointer to the destination (the structure must already exist)
 * @param old pointer to the values, that should be copied
 */
void karma_copy(struct karma *new_instance, struct karma *old) {
    new_instance->val         = old->val;
    new_instance->bytes       = old->bytes;
    new_instance->max         = old->max;
    new_instance->inc         = old->inc;
    new_instance->dec         = old->dec;
    new_instance->penalty     = old->penalty;
    new_instance->restore     = old->restore;
    new_instance->last_update = old->last_update;
    new_instance->reset_meter = old->reset_meter;
}

/**
 * create a new karma structure
 *
 * @param p memory pool to allocate the memory on
 * @return pointer to the newly allocated karam structure
 */
struct karma *karma_new(pool p) {
    struct karma *newk;
    if(p == NULL)
        return NULL;

    newk          = static_cast<struct karma*>(pmalloco(p, sizeof(struct karma)));
    newk->bytes   = 0;
    newk->val     = KARMA_INIT;
    newk->max     = KARMA_MAX;
    newk->inc     = KARMA_INC;
    newk->dec     = KARMA_DEC;
    newk->penalty = KARMA_PENALTY;
    newk->restore = KARMA_RESTORE;
    newk->last_update = 0;
    newk->reset_meter = KARMA_RESETMETER;

    return newk;
}

/**
 * update karma: if karma is incremented, it means that additional bytes are now possible in the configured bandwidth
 *
 * Traffic reduces karma, passed time increments karma
 *
 * @param k the karma structure
 */
void karma_increment(struct karma *k) {
    /* set the current time, and check if we can increment */
    time_t cur_time = time(NULL);
    int punishment_over = 0;
    
    /* only increment every KARMA_HEARTBEAT seconds */
    if( ( k->last_update + KARMA_HEARTBEAT > cur_time ) && k->last_update != 0)
        return;

    /* if incrementing will raise >= 0 */
    if( ( k->val < 0 ) && ( k->val + k->inc >= 0 ) )
        punishment_over = 1;

    /* increment the karma value */
    k->val += k->inc;
    if( k->val > k->max ) k->val = k->max; /* can only be so good */

    /* lower our byte count, if we have good karma */
    if( k->val > 0 ) k->bytes -= ( KARMA_READ_MAX(k->val) );
    if( k->bytes < 0 ) k->bytes = 0;

    /* our karma has *raised* to 0 */
    if( punishment_over )
    /* Set Restore value and clear byte meter */
    {
        k->val = k->restore;
        /* Total absolution for transgression */
        if(k->reset_meter) k->bytes = 0;
    }

    /* reset out counter */
    k->last_update = cur_time;
}

/**
 * update karma: there was traffic, that has to be considered for karma calculations
 *
 * Traffic reduces karma, passed time increments karma
 *
 * @param k the karma structure to update
 * @param bytes_read the ammount of bytes that have been read on a connection, that is karma controlled
 */
void karma_decrement(struct karma *k, long bytes_read) {

    /* Increment the bytes read since last since last karma_increment */
    k->bytes += bytes_read;

    /* Check if our byte meter has exceeded the Max bytes our meter is allowed. */

    if(k->bytes > KARMA_READ_MAX(k->val))
    {
        /* Our meter has exceeded it's allowable lower our karma */
        k->val -= k->dec;

        /* if below zero, set to penalty */
        if(k->val <= 0) k->val = k->penalty;
    }
}

/**
 * check the karma for a connection
 *
 * @param k the karma that should be checked
 * @param bytes_read the number of bytes, that have been read on a connection, that is karma controlled
 * @return 0 on okay check, 1 on bad check
 */
int karma_check(struct karma *k,long bytes_read) {
    /* Check the need to increase or decrease karma */
    karma_increment(k);
    karma_decrement(k, bytes_read);

    /* check its karma */
    if(k->val <= 0)
        return 1; /* bad */

    /* everything is okay */
    return 0;
}
