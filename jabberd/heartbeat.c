#include "jabberd.h"

/* private heartbeat ring struct */
typedef struct beat_struct
{
    beathandler f;
    void *arg;
    int freq;
    int last;
    pool p;
    struct beat_struct *prev;
    struct beat_struct *next;
} *beat, _beat;

/* master hook for the ring */
beat heartbeat__ring;

void *heartbeat(void *arg)
{
    beat b, b2;
    result r;

    while(1)
    {
	pth_sleep(1);

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
}

/* register a function to receive heartbeats */
beat new_beat(void)
{
    beat newb;
    pool p;

    p = pool_new();
    newb = pmalloc_x(p, sizeof(_beat), 0);
    newb->p = p;

    return newb;
}

/* register a function to receive heartbeats */
void register_beat(int freq, beathandler f, void *arg)
{
    beat newb;

    if(freq<=0||f==NULL) return; /* uhh, probbably don't want to allow negative heartbeats, since the counter will count infinitly to a core */

    /* setup the new beat */
    newb = new_beat();
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

/* start up the heartbeat */
void heartbeat_birth(void)
{
    /* init the ring */
    heartbeat__ring = new_beat();
    heartbeat__ring->next = heartbeat__ring->prev = heartbeat__ring;

    /* start the thread */
    pth_spawn(PTH_ATTR_DEFAULT, heartbeat, NULL);
}
