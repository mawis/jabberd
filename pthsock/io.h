#include <jabberd.h>

typedef enum { state_UNKNOWN, state_AUTHD, state_CLOSE } conn_state;

typedef struct wb_q_st
{
    pth_message_t head; /* the standard pth message header */
    xmlnode x;
} _wbq,*wbq;

typedef struct sock_st
{
    pool p;
    conn_state state;
    xstream xs;
    int fd;
    pth_msgport_t queue; /* write buffer queue */
    xmlnode xbuffer;     /* current xmlnode */
    char *wbuffer;       /* current write buffer */
    char *cbuffer;       /* position in write buffer */
    struct sock_st *prev,*next;
    void *arg;    /* yours to define */
    void *cb;     /* do not modify directly */
    void *cb_arg; /* do not modify directly */
    void *iodata; /* do not modify directly */
} *sock, _sock;

/* simple wrapper around the pth messages to pass packets */
typedef struct
{
    pth_message_t head; /* the standard pth message header */
    pool p;
    xmlnode x;
    sock c;
    void *arg;
} *drop, _drop;

typedef void *iosi;

#define IO_INIT 0
#define IO_NEW 1
#define IO_NORMAL 2
#define IO_CLOSED 3
#define IO_ERROR 4

typedef void (*io_onNode)(int type, xmlnode x, void *arg);
typedef void (*io_cb)(sock c,char *buffer,int bufsz,int flags,void *arg);

iosi io_select(int port,io_cb cb,void *arg); /* start listening with select */
void io_write_str(sock c,char *buffer); /* write a str to a socket */
void io_write(sock c,xmlnode x); /*write and eat an xmlnode to the socket */
void io_close(sock c); /* request to close the socket */
void io_select_connect(iosi io_instance,char *host,int port,void *arg);
sock io_select_get_list(iosi io_instance);
