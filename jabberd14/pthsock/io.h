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
#include <jabberd.h>
#include "karma.h"

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
