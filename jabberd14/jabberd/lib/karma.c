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
#include "lib.h"

void karma_copy(struct karma *new, struct karma *old)
{
    new->init        = old->init;
    new->val         = old->val;
    new->bytes       = old->bytes;
    new->max         = old->max;
    new->inc         = old->inc;
    new->dec         = old->dec;
    new->penalty     = old->penalty;
    new->restore     = old->restore;
    new->last_update = old->last_update;
    new->reset_meter = old->reset_meter;
}

struct karma *karma_new(pool p)
{
    struct karma *new;
    if(p == NULL)
        return NULL;

    new          = pmalloco(p, sizeof(struct karma));
    new->init    = 0;
    new->bytes   = 0;
    new->val     = KARMA_DEF_INIT;
    new->max     = KARMA_DEF_MAX;
    new->inc     = KARMA_DEF_INC;
    new->dec     = KARMA_DEF_DEC;
    new->penalty = KARMA_DEF_PENALTY;
    new->restore = KARMA_DEF_RESTORE;
    new->last_update = 0;
    new->reset_meter = KARMA_DEF_RESETMETER;

    return new;
}

void karma_increment(struct karma *k)
{
    /* set the current time, and check if we can increment */
    time_t cur_time = time(NULL);
    int punishment_over = 0;
    
    /* only increment every KARMA_DEF_HEARTBEAT seconds */
    if( ( k->last_update + KARMA_DEF_HEARTBEAT > cur_time ) && k->last_update != 0)
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

void karma_decrement(struct karma *k, long bytes_read)
{

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

/* returns 0 on okay check, 1 on bad check */
int karma_check(struct karma *k,long bytes_read)
{
    /* Check the need to increase or decrease karma */
    karma_increment(k);
    karma_decrement(k, bytes_read);

    /* check its karma */
    if(k->val <= 0)
        return 1; /* bad */

    /* everything is okay */
    return 0;
}
