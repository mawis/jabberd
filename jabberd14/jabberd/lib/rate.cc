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
 * @file rate.cc
 * @brief calculate rate limits
 *
 * Rate limits can be used to limit the number of allowed events in a given interval,
 * e.g. the number of connects from a single IP to the server
 *
 * The events can be weighted.
 */

#include <jabberdlib.h>

/**
 * create a new instance of jlimit that is used to limit events
 *
 * limit the events to maxp points per maxt seconds
 *
 * @param maxt time interval (in seconds) after which the points are cleared
 * @param maxp maximum number of points available for the time interval given in maxt
 * @return new instance of jlimit (has to be freed with jlimit_free if not used anymore)
 */
jlimit jlimit_new(int maxt, int maxp)
{
    pool p;
    jlimit r;

    p = pool_new();
    r = static_cast<jlimit>(pmalloc(p,sizeof(_jlimit)));
    r->key = NULL;
    r->start = r->points = 0;
    r->maxt = maxt;
    r->maxp = maxp;
    r->p = p;

    return r;
}

/**
 * free a jlimit instance
 *
 * @param r the jlimit instance that should be freed
 */
void jlimit_free(jlimit r)
{
    if(r != NULL)
    {
        if(r->key != NULL) free(r->key);
        pool_free(r->p);
    }
}

/**
 * update/check a key in a jlimit instance
 *
 * Each jlimit instance can track many limits (that have the same setup).
 * The limit is selected by the key, which can be an IP address.
 *
 * @param r the jlimit instance
 * @param key for which key the limit should be checked
 * @param points how many points of the limit should be consumed
 * @return 1 if limit reached, 0 if we are still within the rate limit
 */
int jlimit_check(jlimit r, char *key, int points)
{
    int now = time(NULL);

    if(r == NULL) return 0;

    /* make sure we didn't go over the time frame or get a null/new key */
    if((now - r->start) > r->maxt || key == NULL || j_strcmp(key,r->key) != 0)
    { /* start a new key */
        free(r->key);
        if(key != NULL)
	  /* We use strdup instead of pstrdup since r->key needs to be free'd before 
	     and more often than the rest of the rlimit structure */
            r->key = strdup(key); 
        else
            r->key = NULL;
        r->start = now;
        r->points = 0;
    }

    r->points += points;

    /* if we're within the time frame and over the point limit */
    if(r->points > r->maxp && (now - r->start) < r->maxt)
    {
        return 1; /* we don't reset the rate here, so that it remains rated until the time runs out */
    }

    return 0;
}
