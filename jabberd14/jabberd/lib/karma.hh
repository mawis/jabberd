/*
 * Copyrights
 *
 * Portions created by or assigned to Jabber.com, Inc. are
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2019 Matthias Wimmer
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

#ifndef __KARMA_HH
#define __KARMA_HH

#define KARMA_READ_MAX(k)                                                      \
    (abs(k) * 100)        /* how much you are allowed to read off the sock */
#define KARMA_INIT 5      /* internal "init" value */
#define KARMA_HEARTBEAT 2 /* seconds to register for heartbeat */
#define KARMA_MAX 10      /* total max karma you can have */
#define KARMA_INC 1 /* how much to increment every KARMA_HEARTBEAT seconds */
#define KARMA_DEC                                                              \
    0                    /* how much to penalize for reading KARMA_READ_MAX in \
                            KARMA_HEARTBEAT seconds */
#define KARMA_PENALTY -5 /* where you go when you hit 0 karma */
#define KARMA_RESTORE 5  /* where you go when you payed your penelty or INIT */
#define KARMA_RESETMETER 0 /* Reset byte meter on restore default is falst */

struct karma {
    int reset_meter;      /* reset the byte meter on restore */
    int val;              /* current karma value */
    long bytes;           /* total bytes read (in that time period) */
    int max;              /* max karma you can have */
    int inc, dec;         /* how much to increment/decrement */
    int penalty, restore; /* what penalty (<0) or restore (>0) */
    time_t last_update;   /* time this was last incremented */
};

struct karma *
karma_new(pool p); /* creates a new karma object, with default values */
void karma_copy(struct karma *new_instance,
                struct karma *old);    /* makes a copy of old in new */
void karma_increment(struct karma *k); /* inteligently increments karma */
void karma_decrement(struct karma *k,
                     long bytes_read); /* inteligently decrements karma */
int karma_check(struct karma *k,
                long bytes_read); /* checks to see if we have good karma */

#endif // __KARMA_HH
