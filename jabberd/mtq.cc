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

#include "jabberd.h"

/**
 * @file mtq.cc
 * @brief mtq is Managed Thread Queues - it manages the multithreading in jabberd
 *
 * they queue calls to be run sequentially on a thread, that comes from a system pool of threads
 */

typedef struct mtqcall_struct {
    pth_message_t head;	/**< the standard pth message header */
    mtq_callback f;	/**< function to run within the thread */
    void *arg;		/**< the data for this call */
    mtq q;		/**< if this is a queue to process */
} _mtqcall, *mtqcall;

typedef struct mtqmaster_struct {
    mth all[MTQ_THREADS];
    int overflow;
    pth_msgport_t mp;
} *mtqmaster, _mtqmaster;

mtqmaster mtq__master = NULL;

/**
 * cleanup a queue when it get's free'd
 */
static void mtq_cleanup(void *arg) {
    mtq q = (mtq)arg;
    mtqcall c;

    /* if there's a thread using us, make sure we disassociate ourselves with them */
    if (q->t != NULL)
        q->t->q = NULL;

    /* What?  not empty?!?!?! probably a programming/sequencing error! */
    while ((c = (mtqcall)pth_msgport_get(q->mp)) != NULL) {
        log_debug2(ZONE, LOGT_THREAD|LOGT_STRANGE, "%X last call %X",q->mp,c->arg);
        (*(c->f))(c->arg);
    }
    pth_msgport_destroy(q->mp);
}

/**
 * public queue creation function, queue lives as long as the pool
 */
mtq mtq_new(pool p) {
    mtq q;

    if (p == NULL)
	return NULL;

    log_debug2(ZONE, LOGT_THREAD, "MTQ(new)");

    /* create queue */
    q = static_cast<mtq>(pmalloco(p, sizeof(_mtq)));

    /* create msgport */
    q->mp = pth_msgport_create("mtq");

    /* register cleanup handler */
    pool_cleanup(p, mtq_cleanup, (void *)q);

    return q;
}

/**
 * main slave thread
 */
static void *mtq_main(void *arg) {
    mth t = (mth)arg;
    pth_event_t mpevt;
    mtqcall c;

    log_debug2(ZONE, LOGT_THREAD|LOGT_INIT, "%X starting",t->id);

    /* create an event ring for receiving messges */
    mpevt = pth_event(PTH_EVENT_MSG,t->mp);

    /* loop */
    while(1) {

        /* before checking our mp, see if the master one has overflow traffic in it */
        if(mtq__master->overflow) {
            /* get the call from the master */
            c = (mtqcall)pth_msgport_get(mtq__master->mp);
            if(c == NULL) {
		/* empty! */
                mtq__master->overflow = 0;
                continue;
            }
        } else {
            /* debug: note that we're waiting for a message */
            log_debug2(ZONE, LOGT_THREAD, "%X leaving to pth",t->id);
            t->busy = 0;

            /* wait for a master message on the port */
            pth_wait(mpevt);

            /* debug: note that we're working */
            log_debug2(ZONE, LOGT_THREAD, "%X entering from pth",t->id);
            t->busy = 1;

            /* get the message */
            c = (mtqcall)pth_msgport_get(t->mp);
            if(c == NULL) continue;
        }


        /* check for a simple "one-off" call */
        if(c->q == NULL) {
            log_debug2(ZONE, LOGT_THREAD, "%X one call %X",t->id,c->arg);
            (*(c->f))(c->arg);
            continue;
        }

        /* we've got a queue call, associate ourselves and process all it's packets */
        t->q = c->q;
        t->q->t = t;
        while((c = (mtqcall)pth_msgport_get(t->q->mp)) != NULL) {
            log_debug2(ZONE, LOGT_THREAD, "%X queue call %X",t->id,c->arg);
            (*(c->f))(c->arg);
            if(t->q == NULL)
		break;
        }

        /* disassociate the thread and queue since we processed all the packets */
        /* XXX future pthreads note: mtq_send() could have put another call on the queue since we exited the while, that would be bad */
        if(t->q != NULL) {
            t->q->t = NULL; /* make sure the queue doesn't point to us anymore */
            t->q->routed = 0; /* nobody is working on the queue anymore */
            t->q = NULL; /* we're not working on the queue */
        }

    }

    /* free all memory stuff associated with the thread */
    pth_event_free(mpevt,PTH_FREE_ALL);
    pth_msgport_destroy(t->mp);
    pool_free(t->p);
    return NULL;
}

void mtq_send(mtq q, pool p, mtq_callback f, void *arg) {
    mtqcall c;
    mth t = NULL;
    int n; pool newp;
    pth_msgport_t mp = NULL; /* who to send the call too */
    pth_attr_t attr;

    /* initialization stuff */
    if(mtq__master == NULL) {
	mtq__master = new _mtqmaster;
        mtq__master->mp = pth_msgport_create("mtq__master");
        for(n=0;n<MTQ_THREADS;n++) {
            newp = pool_new();
            t = static_cast<mth>(pmalloco(newp, sizeof(_mth)));
            t->p = newp;
            t->mp = pth_msgport_create("mth");
            attr = pth_attr_new();
            pth_attr_set(attr, PTH_ATTR_PRIO, PTH_PRIO_MAX);
            t->id = pth_spawn(attr, mtq_main, (void *)t);
            pth_attr_destroy(attr);
            mtq__master->all[n] = t; /* assign it as available */
        }
    }

    /* find a waiting thread */
    for(n = 0; n < MTQ_THREADS; n++)
        if(mtq__master->all[n]->busy == 0) {
            mp = mtq__master->all[n]->mp;
            break;
        }

    /* if there's no thread available, dump in the overflow msgport */
    if(mp == NULL) {
        log_debug2(ZONE, LOGT_THREAD, "%d overflowing %X",mtq__master->overflow,arg);
        mp = mtq__master->mp;
        /* XXX this is a race condition in pthreads.. if the overflow
         * is not put on the mp, before a worker thread checks the mp
         * for messages, then it will set this variable to 0 and not
         * check the overflow mp until another item overflows it */
        mtq__master->overflow++;
    }

    /* track this call */
    c = static_cast<mtqcall>(pmalloco(p, sizeof(_mtqcall)));
    c->f = f;
    c->arg = arg;

    /* if we don't have a queue, just send it */
    if(q == NULL) {
        pth_msgport_put(mp, (pth_message_t *)c);
        /* if we use a thread, mark it busy */
        if(mp != mtq__master->mp)
            mtq__master->all[n]->busy = 1;
        return;
    }

    /* if we have a queue, insert it there */
    pth_msgport_put(q->mp, (pth_message_t *)c);

    /*if(pth_msgport_pending(q->mp) > 10)
        log_debug2(ZONE, LOGT_THREAD, "%d queue overflow on %X",pth_msgport_pending(q->mp),q->mp);*/

    /* if we haven't told anyone to take this queue yet */
    if(q->routed == 0) {
        c = static_cast<mtqcall>(pmalloco(p, sizeof(_mtqcall)));
        c->q = q;
        pth_msgport_put(mp, (pth_message_t *)c);
        /* if we use a thread, mark it busy */
        if(mp != mtq__master->mp)
            mtq__master->all[n]->busy = 1;
        q->routed = 1;
    }
}
