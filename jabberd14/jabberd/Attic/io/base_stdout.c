/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  Jabber
 *  Copyright (C) 1998-1999 The Jabber Team http://jabber.org/
 */

#include "jabberd.h"

/*

<stdout/>

with this flag in any instance of any type, it causes all packets to be delivered to standard out (STDOUT) from the jabberd process
it also flags a thread to read on STDIN for incoming packets

*/

/* simple wrapper around the pth messages to pass packets */
typedef struct
{
    pth_message_t head; /* the standard pth message header */
    dpacket p;
} *drop, _drop;

/* write packets to sink */
result base_stdout_phandler(instance i, dpacket p, void *arg)
{
    pth_msgport_t mp = (pth_msgport_t)arg;
    drop d;

    log_debug(ZONE,"stdout packet being queued");

    d = pmalloco(p->p, sizeof(_drop));
    d->p = p;

    pth_msgport_put(mp, (pth_message_t *)d);

    return r_DONE;
}

void base_stdin_packets(int type, xmlnode x, void *arg)
{
    switch(type)
    {
    case XSTREAM_ROOT:
        log_debug(ZONE,"stdin opened stream");
        break;
    case XSTREAM_NODE:
        /* deliver the packets coming on stdin... they aren't associated with an instance really */
        log_debug(ZONE,"stdin incoming packet");
        deliver(dpacket_new(x), NULL); 
        break;
    default:
    }

}

/* thread to handle io from socket */
void *base_stdoutin(void *arg)
{
    pth_msgport_t mp = (pth_msgport_t)arg;
    xstream xs;
    int len;
    char buff[1024], *block;
    dpacket p = NULL;
    drop d;
    xmlnode x;
    pth_event_t eread, emp, ering;
    pool xsp;

    log_debug(ZONE,"io thread starting");

    /* send the header to stdout */
    x = xstream_header("jabberd:sockets",NULL,NULL);
    block = xstream_header_char(x);
    pth_write(STDOUT_FILENO,block,strlen(block));
    xmlnode_free(x);

    /* start xstream and event for reading packets from stdin */
    xsp = pool_new();
    xs = xstream_new(xsp, base_stdin_packets, NULL);
    eread = pth_event(PTH_EVENT_FD|PTH_UNTIL_FD_READABLE,STDIN_FILENO);

    /* event for packets going to stdout and ring em all together */
    emp = pth_event(PTH_EVENT_MSG,mp);
    ering = pth_event_concat(eread, emp, NULL);

    /* spin waiting on the mp(stdout) or read(stdin) events */
    while(pth_wait(ering) > 0)
    {
        /* handle reading the incoming stream */
        if(pth_event_occurred(eread))
        {
            log_debug(ZONE,"stdin read event");
            len = pth_read(STDIN_FILENO, buff, 1024);
            if(len <= 0) break;

            if(xstream_eat(xs, buff, len) > XSTREAM_NODE) break;
        }

        /* handle the packets to be sent to the socket */
        if(pth_event_occurred(emp))
        {
            log_debug(ZONE,"io incoming message event for stdout");

            /* get packet */
            d = (drop)pth_msgport_get(mp);
            p = d->p;

            /* write packet phase */
            block = xmlnode2str(p->x);
            if(pth_write(STDOUT_FILENO, block, strlen(block)) <= 0)
                break;

            /* all sent, yay */
            pool_free(p->p);
            p = NULL;
        }

    }

    log_debug(ZONE,"thread exiting");

    /* we shouldn't ever get here, I don't think */
    pth_event_free(emp, PTH_FREE_THIS);
    pth_event_free(eread, PTH_FREE_THIS);
    pool_free(xsp);

    return NULL;
}

result base_stdout_config(instance id, xmlnode x, void *arg)
{
    static pth_msgport_t mp = NULL;

    if(id == NULL) return r_PASS;

    log_debug(ZONE,"base_stdout_config performing configuration");

    /* create the mp and start the io thread only once */
    if(mp == NULL)
    {
        mp = pth_msgport_create("base_stdout");
        pth_spawn(PTH_ATTR_DEFAULT, base_stdoutin, (void *)mp);
    }

    /* register phandler with the stdout mp */
    register_phandler(id, o_DELIVER, base_stdout_phandler, (void *)mp);

    return r_DONE;
}

void base_stdout(void)
{
    log_debug(ZONE,"base_stdout loading...\n");

    register_config("stdout",base_stdout_config,NULL);
}
