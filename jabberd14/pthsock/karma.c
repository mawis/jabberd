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
 * --------------------------------------------------------------------------*/
#include "io.h"

void karma_copy(struct karma *new, struct karma *old)
{
    new->val=old->val;
    new->bytes=old->bytes;
    new->max=old->max;
    new->inc=old->inc;
    new->dec=old->dec;
    new->penalty=old->penalty;
    new->restore=old->restore;
}

void karma_increment(struct karma *k)
{
    /* set the current time, and check if we can increment */
    time_t cur_time = time(NULL);
    int punishment_over = 0;
    
    /* only increment every KARMA_HEARTBEAT seconds */
    if( ( k->last_update + KARMA_HEARTBEAT > cur_time ) && k->last_update != 0)
        return;

    /* if incrementing will raise over 0 */
    if( ( k->val < 0 ) && ( k->val + k->inc > 0 ) )
        punishment_over = 1;

    /* increment the karma value */
    k->val += k->inc;
    if( k->val > k->max ) k->val = k->max; /* can only be so good */

    /* lower our byte count, if we have good karma */
    if( k->val > 0 ) k->bytes -= ( KARMA_READ_MAX(k->val) );
    if( k->bytes <0 ) k->bytes = 0;

    /* our karma has *raised* to 0 */
    if( punishment_over )
    {
        k->val = k->restore;
        /* XXX call back for no more punishment */
    }

    /* reset out counter */
    k->last_update = cur_time;
}

void karma_decrement(struct karma *k)
{
    /* lower our karma */
    k->val -= k->dec;

    /* if below zero, set to penalty */
    if( k->val <= 0 ) 
        k->val = k->penalty;
}

/* returns 0 on okay check, 1 on bad check */
int karma_check(struct karma *k,long bytes_read)
{
    /* first, check for need to update */
    if( ( k->last_update + KARMA_HEARTBEAT < time(NULL) ) || k->last_update == 0)
        karma_increment( k );

    /* next, add up the total bytes */
    k->bytes += bytes_read;
    if( k->bytes > KARMA_READ_MAX(k->val) )
        karma_decrement( k );

    /* check if it's okay */
    if( k->val <= 0 )
        return 1;

    /* everything is okay */
    return 0;
}
