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

typedef enum { queue_XMLNODE, queue_TEXT } queue_type;
typedef struct wb_q_st
{
    pth_message_t head; /* the standard pth message header */
    pool p;
    queue_type type;
    xmlnode x;
    char *data;
} _wbq,*wbq;

struct karma
{
    int val;
    long bytes;
    int max;
    int inc,dec;
    int penalty,restore;
};

typedef enum { state_ACTIVE, state_CLOSE } conn_state;
typedef enum { type_LISTEN, type_NORMAL } sock_type;
typedef struct sock_st
{
    pool p;
    sock_type type;
    int rated;   /* is this socket rate limted? */
    jlimit rate; /* if so, what is the rate?    */
    conn_state state;
    xstream xs;
    int fd;
    pth_msgport_t queue; /* write buffer queue */
    xmlnode xbuffer;     /* current xmlnode */
    char *wbuffer;       /* current write buffer */
    char *cbuffer;       /* position in write buffer */
    pool pbuffer;        /* a pointer to the pool this buffer is using */
    struct sock_st *prev,*next;
    void *arg;    /* yours to define */
    void *cb;     /* do not modify directly */
    void *cb_arg; /* do not modify directly */
    struct karma k;
} *sock, _sock;

typedef void *iosi;

#define IO_INIT 0
#define IO_NEW 1
#define IO_NORMAL 2
#define IO_CLOSED 3
#define IO_ERROR 4
// #define KARMA_DEBUG
#define KARMA_READ_MAX(k) k*100 /* how much you are allowed to read off the sock */
#define KARMA_INIT -10   /* internal "init" value, should not be able to get here */
#define KARMA_HEARTBEAT 2 /* seconds to register for heartbeat */
#define KARMA_MAX 10     /* total max karma you can have */
#define KARMA_INC 1      /* how much to increment every KARMA_HEARTBEAT seconds */
#define KARMA_DEC 1      /* how much to penalize for reading KARMA_READ_MAX in
                            KARMA_HEARTBEAT seconds */
#define KARMA_PENALTY -5 /* where you go when you hit 0 karma */
#define KARMA_RESTORE 5  /* where you go when you payed your penelty or INIT */

typedef void (*io_onNode)(int type, xmlnode x, void *arg);
typedef void (*io_cb)(sock c,char *buffer,int bufsz,int flags,void *arg);
void io_select_listen(int port,char *listen_host,io_cb cb,void *arg,int rate_time,int max_points); /* start listening with select */
void io_select_listen_ex(int port,char *listen_host,io_cb cb,void *arg,int rate_time,int max_points,struct karma *k); /* start listening with select */
void io_write_str(sock c,char *buffer); /* write a str to a socket */
void io_write(sock c,xmlnode x); /*write and eat an xmlnode to the socket */
void io_close(sock c); /* request to close the socket */
void io_select_connect(char *host,int port,void *arg,io_cb cb,void *cb_arg); /* connect */
void io_select_connect_ex(char *host,int port,void *arg,io_cb cb,void *cb_arg,struct karma *k); /* connect */
sock io_select_get_list(void); /* returns a list of sockets */
