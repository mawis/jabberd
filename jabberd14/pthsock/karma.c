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
    time_t cur_time = time(NULL);
    int punishment_over = 0;
    if( ( k->last_update + KARMA_HEARTBEAT > cur_time ) && k->last_update != 0)
        return;
    if( ( k->val < 0 ) && ( k->val + k->inc > 0 ) )
        punishment_over = 1;
    k->val += k->inc;
    if( k->val > k->max ) k->val = k->max; /* can only be so good */
    if( k->val > 0 ) k->bytes -= ( KARMA_READ_MAX(k->val) );
    if( k->bytes <0 ) k->bytes = 0;
    if( punishment_over )
    {
        k->val = k->restore;
        /* call back for no more punishment */
    }
    k->last_update = cur_time;
}

void karma_decrement(struct karma *k)
{
    k->val -= k->dec;
    if( k->val <= 0 ) 
        k->val = k->penalty;
}

/* returns 0 on okay check, 1 on bad check */
int karma_check(struct karma *k,long bytes_read)
{
    /* first, check for need to update */
    if( k->last_update > time(NULL) + KARMA_HEARTBEAT )
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
