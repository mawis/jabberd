/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "JOSL").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the JOSL. You
 * may obtain a copy of the JOSL at http://www.jabber.org/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the JOSL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the JOSL
 * for the specific language governing rights and limitations under the
 * JOSL.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 or later (the "GPL"), in which case
 * the provisions of the GPL are applicable instead of those above.  If you
 * wish to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the JOSL,
 * indicate your decision by deleting the provisions above and replace them
 * with the notice and other provisions required by the GPL.  If you do not
 * delete the provisions above, a recipient may use your version of this file
 * under either the JOSL or the GPL. 
 * 
 * --------------------------------------------------------------------------*/
#include "mio.h"

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
    new->val     = KARMA_INIT;
    new->max     = KARMA_MAX;
    new->inc     = KARMA_INC;
    new->dec     = KARMA_DEC;
    new->penalty = KARMA_PENALTY;
    new->restore = KARMA_RESTORE;
    new->last_update = 0;
    new->reset_meter = KARMA_RESETMETER;

    return new;
}

void karma_increment(struct karma *k)
{
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

jlimit jlimit_new(int maxt, int maxp)
{
    pool p;
    jlimit r;

    p = pool_new();
    r = pmalloc(p,sizeof(_jlimit));
    r->key = NULL;
    r->start = r->points = 0;
    r->maxt = maxt;
    r->maxp = maxp;
    r->p = p;

    return r;
}

void jlimit_free(jlimit r)
{
    if(r != NULL)
    {
        if(r->key != NULL) free(r->key);
        pool_free(r->p);
    }
}

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
