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

typedef enum { state_ACTIVE, state_CLOSE } conn_state;
typedef enum { type_LISTEN, type_NORMAL } sock_type;
typedef struct sock_st
{
    pool p;
    sock_type type;
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
    void *iodata; /* do not modify directly */
} *sock, _sock;

typedef void *iosi;

#define IO_INIT 0
#define IO_NEW 1
#define IO_NORMAL 2
#define IO_CLOSED 3
#define IO_ERROR 4

typedef void (*io_onNode)(int type, xmlnode x, void *arg);
typedef void (*io_cb)(sock c,char *buffer,int bufsz,int flags,void *arg);

void io_select_listen(int port,char *listen_host,io_cb cb,void *arg); /* start listening with select */
void io_write_str(sock c,char *buffer); /* write a str to a socket */
void io_write(sock c,xmlnode x); /*write and eat an xmlnode to the socket */
void io_close(sock c); /* request to close the socket */
void io_select_connect(char *host,int port,void *arg,io_cb cb,void *cb_arg); /* connect */
sock io_select_get_list(void); /* returns a list of sockets */
