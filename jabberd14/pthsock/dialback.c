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
 *  Copyright (C) 1998-2000 The Jabber Team http://jabber.org/
 */

#include <jabberd.h>

typedef enum { state_START, state_OK } ipstate;

typedef struct dbip_struct
{
    ipstate state;
    char *ipp;      /* the ip:port */
    sock s;         /* socket once it's connected */
    pool p;         /* pool for this struct */
    pool pre_ok;    /* pool for queing activity that happens as soon as the socket is spiffy */
} *dbip, _dbip;

typedef enum { htype_IN, htype_OUT } htype;

typedef struct dbhost_struct
{
    /* used for in and out connections */
    htype type;     /* type of host, in or out */
    jid id;         /* the funky id for the hashes, to/from */
    char *to;       /* who we're connected to (out), or who we are (in) */
    char *from;     /* reverse of to :) */
    int valid;      /* flag if we've been validated */
    ssi si;         /* instance tracker */

    /* outgoing connections only */
    dbip ip;        /* the ip we're connected on */
    pth_msgport_t mp; /* the waiting-for-validation queue */

    /* incoming connections */
    sock s;         /* the incoming connection that we're associated with */

} *dbhost, _dbhost;

/* cleans up the host (removes from hashes) */
void dbhost_cleanup(void *arg); 

/* is called when the dbip gets connected, to send a result or verify packet */
void dbhost_sendspecial(void *arg);

/* sends packet out (or bounces or drops) */
result pthsock_server_packets(instance i, dpacket dp, void *arg)
{
    ssi si = (ssi) arg;
    dbhost h;
    dbip ip;
    jid to, from;
    xmlnode x;

    /* unwrap the route packet */
    x = xmlnode_get_firstchild(dp->x);

    to = jid_new(dp->p,xmlnode_get_attrib(x,"to"));
    from = jid_new(dp->p,xmlnode_get_attrib(x,"from"));
    jid_set(id,NULL,JID_USER);

    get the id
    host = ghash_get(si->hashout,id)
    if(host == NULL)
        ip = ghash_get(si->haship,ip);
        if(ip == NULL)
            new ip
            connect(ip)
        new host
        cleanup when ip dies
        ghash_put
        if ip->state != state_OK
            cleanup when ip->pre_ok to generate and send a db:result
        else
            send db:result

    if(host->valid)
        send to host->ip->sock
        return;

    if packet is a db:verify
        if(host->ip->state != state_OK)
            cleanup when ip->pre_ok to generate and send the packet
        else
            send db:verify on
    else
        queue

}

outconn_read
    if(db:result)
        host = ghash_get(si->hashout)
        if(host->outconn != us)
            log_notice and drop?
        host->valid = 1
        empty host->queue onto the wire
    if(db:verify)
        if(ghash_get(si->hashout) && that->outconn == us)
            were getting a verify with invalid to/from, drop conn
        host = ghash_get(si->hashin)
        if(host == NULL)
            log_notice
        host->valid = 1;
        write(host->sock

inconn_read
    if(db:result)
        new host, valid=0, cleanup on inconn pool to take out of ghash
        ghash_put si->hashin
        forward verify into deliver, going back to sender on outconn
        return
    if(db:verify)
        send response
        return
    host = ghash_get(si->hashin)
    if host->valid && host->s == us
        send
    else
        drop connection


UGH, handle multiple inconns from the same to/from, other side is multiple nodes on a farm

A->B
    A: <db:result to=B from=A>...</db:result>
B->A
    B: <db:verify to=A from=B>...</db:verify>
    A: <db:verify type="valid" to=B from=A/>
A->B
    B: <db:result type="valid" to=A from=B/>
