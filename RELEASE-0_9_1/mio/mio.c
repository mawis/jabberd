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

/**
 * @file mio.c
 * @brief MIO -- Managed Input/Output
 *
 * Implementation of mio.
 */

#include "mio.h"
#ifdef MIO_POLL
#include "mio_poll.h"
#endif
#ifdef MIO_SELECT
#include "mio_select.h"
#endif

#include <sys/socket.h>
#include <netinet/tcp.h>

/**
 * type of a file descriptor
 */
typedef enum { 
    type_CLOSED = 0x00,		/**< fd is closed */
    type_NORMAL = 0x01,
    type_LISTEN = 0x02,		/**< socket is listening for new conns */ 
    type_CONNECT = 0x10, 
    type_CONNECT_READ = 0x11,
    type_CONNECT_WRITE = 0x12
} mio_type_t;

/**
 * our internal wrapper around a fd
 */
struct mio_fd_st
{
    mio_type_t type;
    mio_handler_t app;		/**< application callback for actions */
    time_t last_activity;	/**< last activity on fd, for idle detection */
    void *arg;			/**< argument to pass to the callback func */
};

/**
 * mio master data type, holds the mio instance-global data
 */
struct mio_st
{
    struct mio_fd_st *fds;
    int maxfd;
    int highfd;
    time_t last_idle_check;
    MIO_VARS;
};

/**
 * accessor macro for a fd
 */
#define FD(m,f) m->fds[f]

/**
 * send an event to the registered callback
 */
#define ACT(m,f,a,d) (*(FD(m,f).app))(m,a,f,d,FD(m,f).arg)

/* temp debug outputter */
#define ZONE __LINE__
#ifndef DEBUG
# define DEBUG 0
#else
# undef DEBUG
# define DEBUG 1
#endif
#define mio_debug if(DEBUG) _mio_debug
static void _mio_debug(int line, const char *msgfmt, ...)
{
    va_list ap;
    char *pos;
    int sz;
    time_t t;

    /* timestamp */
    t = time(NULL);
    pos = ctime(&t);
    sz = strlen(pos);
    /* chop off the \n */
    pos[sz-1]=' ';

    va_start(ap,msgfmt);
    fprintf(stderr,"%smio.c#%d: ",pos,line);
    vfprintf(stderr,msgfmt,ap);
    fprintf(stderr,"\n");
}

MIO_FUNCS

/* internal close function */
void mio_close(mio_t m, int fd)
{
    mio_debug(ZONE,"actually closing fd #%d",fd);

    /* take out of poll sets */
    MIO_REMOVE_FD(m, fd);

    /* let the app know, it must process any waiting write data it has and free it's arg */
    ACT(m, fd, action_CLOSE, NULL);

    /* close the socket, and reset all memory */
    close(fd);
    memset(&FD(m,fd), 0, sizeof(struct mio_fd_st));
}

/**
 * internally accept an incoming connection from a listen sock
 *
 * @param m the mio on which the connection is accepted
 * @param fd the fd of the incoming connection
 */
static void _mio_accept(mio_t m, int fd)
{
#ifdef USE_IPV6
    struct sockaddr_storage serv_addr;
    char ip[INET6_ADDRSTRLEN];
    int port = 0;
#else
    struct sockaddr_in serv_addr;
    char ip[16];
#endif
    size_t addrlen = sizeof(serv_addr);
    int newfd, dupfd;

    mio_debug(ZONE, "accepting on fd #%d", fd);

    /* pull a socket off the accept queue and check */
    newfd = accept(fd, (struct sockaddr*)&serv_addr, (socklen_t *)&addrlen);
    if(newfd <= 0) return;

#ifdef USE_IPV6
    switch (serv_addr.ss_family) {
	case AF_INET:
	    inet_ntop(AF_INET, &(((struct sockaddr_in*)&serv_addr)->sin_addr), ip, sizeof(ip));
	    port = ntohs(((struct sockaddr_in*)&serv_addr)->sin_port);
	    break;
	case AF_INET6:
	    inet_ntop(AF_INET6, &(((struct sockaddr_in6*)&serv_addr)->sin6_addr), ip, sizeof(ip));
	    port = ntohs(((struct sockaddr_in6*)&serv_addr)->sin6_port);
	    break;
	default:
	    strcpy(ip, "(unknown)");
    }
    mio_debug(ZONE, "new socket accepted fd #%d, ip %s, port %d", newfd, ip, port);
#else
    snprintf(ip,16,"%s",inet_ntoa(serv_addr.sin_addr));
    mio_debug(ZONE, "new socket accepted fd #%d, %s:%d", newfd, ip, ntohs(serv_addr.sin_port));
#endif

    /* set up the entry for this new socket */
    if(mio_fd(m, newfd, FD(m,fd).app, FD(m,fd).arg) < 0)
    {
        /* too high, try and get a lower fd */
        dupfd = dup(newfd);
        close(newfd);

        if(dupfd < 0 || mio_fd(m, dupfd, FD(m,fd).app, FD(m,fd).arg) < 0) {
            mio_debug(ZONE,"failed to add fd");
            if(dupfd >= 0) close(dupfd);

            return;
        }

        newfd = dupfd;
    }

    /* tell the app about the new socket, if they reject it clean up */
    if (ACT(m, newfd, action_ACCEPT, ip))
    {
        mio_debug(ZONE, "accept was rejected for %s:%d", ip, newfd);
        MIO_REMOVE_FD(m, newfd);

        /* close the socket, and reset all memory */
        close(newfd);
        memset(&FD(m, newfd), 0, sizeof(struct mio_fd_st));
    }

    return;
}

/**
 * internally change a connecting socket to a normal one
 */
static void _mio_connect(mio_t m, int fd)
{
    mio_type_t type = FD(m,fd).type;

    mio_debug(ZONE, "connect processing for fd #%d", fd);

    /* reset type and clear the "write" event that flags connect() is done */
    FD(m,fd).type = type_NORMAL;
    MIO_UNSET_WRITE(m,fd);

    /* if the app had asked to do anything in the meantime, do those now */
    if(type & type_CONNECT_READ) mio_read(m,fd);
    if(type & type_CONNECT_WRITE) mio_write(m,fd);
}

/* add and set up this fd to this mio */
int mio_fd(mio_t m, int fd, mio_handler_t app, void *arg)
{
    int flags;

    mio_debug(ZONE, "adding fd #%d", fd);

    if(fd >= m->maxfd)
    {
        mio_debug(ZONE,"fd to high");
        return -1;
    }

    /* ok to process this one, welcome to the family */
    FD(m,fd).type = type_NORMAL;
    FD(m,fd).app = app;
    FD(m,fd).last_activity = time(NULL);
    FD(m,fd).arg = arg;
    MIO_INIT_FD(m, fd);

    /* set the socket to non-blocking */
    flags =  fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);

    /* track highest used */
    if(fd > m->highfd) m->highfd = fd;

    return fd;
}

/* reset app stuff for this fd */
void mio_app(mio_t m, int fd, mio_handler_t app, void *arg)
{
    FD(m,fd).app = app;
    FD(m,fd).arg = arg;
}

/* main select loop runner */
void mio_run(mio_t m, int timeout)
{
    int retval, fd;
    time_t now;

    mio_debug(ZONE, "mio running for %d", timeout);

    /* wait for a socket event */
    retval = MIO_CHECK(m, timeout);
    now = time(NULL);

    /* nothing to do */
    /* XXX Make 300 a config option? */
    if(retval == 0 && (now - m->last_idle_check) < 300) return;
    
    /* reset the idle check counter */
    m->last_idle_check = now;

    /* an error */
    if(retval < 0)
    {
        mio_debug(ZONE, "MIO_CHECK returned an error (%d)", MIO_ERROR(m));

        return;
    }

    mio_debug(ZONE,"mio working: %d",retval);

    /* loop through the sockets, check for stuff to do */
    for(fd = 0; fd <= m->highfd; fd++)
    {
        int isActive = 0;

        /* skip dead slots */
        if(FD(m,fd).type == type_CLOSED) continue;

        /* new conns on a listen socket */
        if(FD(m,fd).type == type_LISTEN && MIO_CAN_READ(m, fd))
        {
            _mio_accept(m, fd);
            continue;
        }

        /* check for connecting sockets */
        if(FD(m,fd).type & type_CONNECT && MIO_CAN_WRITE(m, fd))
        {
            _mio_connect(m, fd);
            continue;
        }

        /* read from ready sockets */
        if(FD(m,fd).type == type_NORMAL && MIO_CAN_READ(m, fd))
        {
            /* if they don't want to read any more right now */
            if(ACT(m, fd, action_READ, NULL) == 0)
                MIO_UNSET_READ(m, fd);
            isActive = 1;
        }

        /* write to ready sockets */
        if(FD(m,fd).type == type_NORMAL && MIO_CAN_WRITE(m, fd))
        {
            /* don't wait for writeability if nothing to write anymore */
            if(ACT(m, fd, action_WRITE, NULL) == 0)
                MIO_UNSET_WRITE(m, fd);
            isActive = 1;
        }

        /* Idle tests */
        if (FD(m,fd).type == type_NORMAL)
        {
            if (isActive)
            {
                /* Set the last time the fd had activity */
                FD(m,fd).last_activity = time(NULL);
            }
            else
            {
                /* If it's been too long, fire an idle check */
                if ( (time(NULL) - FD(m,fd).last_activity) >= 300 )
                {
                    if(ACT(m, fd, action_IDLE, NULL))
                    {
                        mio_debug(ZONE, "Socket %d has idled to death", fd);
                        mio_close(m, fd);
                    }

		    /* We have send a space, wait again until we send the next */
		    FD(m,fd).last_activity = time(NULL);
		}
            }
        }
            
    } 
}

/* eve */
mio_t mio_new(int maxfd)
{
    mio_t m;

    /* allocate and zero out main memory */
    if((m = malloc(sizeof(struct mio_st))) == NULL) return NULL;
    if((m->fds = malloc(sizeof(struct mio_fd_st) * maxfd)) == NULL)
    {
        mio_debug(ZONE,"internal error creating new mio");
        free(m);
        return NULL;
    }
    memset(m->fds, 0, sizeof(struct mio_fd_st) * maxfd);

    /* set up our internal vars */
    m->maxfd = maxfd;
    m->highfd = 0;
    m->last_idle_check = time(NULL);

    MIO_INIT_VARS(m);

    return m;
}

/* adam */
void mio_free(mio_t m)
{
    MIO_FREE_VARS(m);

    free(m->fds);
    free(m);
}

/* start processing read events */
void mio_read(mio_t m, int fd)
{
    if(m == NULL || fd < 0) return;

    /* if connecting, do this later */
    if(FD(m,fd).type & type_CONNECT)
    {
        FD(m,fd).type |= type_CONNECT_READ;
        return;
    }

    MIO_SET_READ(m, fd);
}

/* try writing to the socket via the app */
void mio_write(mio_t m, int fd)
{
    if(m == NULL || fd < 0) return;

    /* if connecting, do this later */
    if(FD(m,fd).type & type_CONNECT)
    {
        FD(m,fd).type |= type_CONNECT_WRITE;
        return;
    }

    if(ACT(m, fd, action_WRITE, NULL) == 0) return;

    /* not all written, do more l8r */
    MIO_SET_WRITE(m, fd);
}

/* set up a listener in this mio w/ this default app/arg */
int mio_listen(mio_t m, int port, char *sourceip, mio_handler_t app, void *arg)
{
    int fd, flag = 1, af = AF_INET;
#ifdef USE_IPV6
    struct in_addr ipv4;
    struct in6_addr ipv6;
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
    struct sockaddr *sa;
    socklen_t addrlen;
#else
    unsigned long int ip = 0;
    struct sockaddr_in sa;
#endif

    if(m == NULL) return -1;

    mio_debug(ZONE, "mio to listen on %d [%s]", port, sourceip);

    /* if we specified an ip to bind to */
    if(sourceip != NULL) {
#ifdef USE_IPV6
	if (inet_pton(AF_INET, sourceip, &ipv4) > 0) {
	    af = AF_INET;
	} else if (inet_pton(AF_INET6, sourceip, &ipv6) > 0) {
	    af = AF_INET6;
	} else {
	    /* XXX If source ip is not parsealbe, we just ignore it ... better error handling */
	    sourceip = NULL;
	}
#else
        ip = inet_addr(sourceip);
#endif
    }

    /* attempt to create a socket */
    if((fd = socket(af,SOCK_STREAM,0)) < 0) return -1;
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&flag, sizeof(flag)) < 0) return -1;
    if(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag)) < 0)
        return(-1);

    /* set up and bind address info */
#ifdef USE_IPV6
    switch(af) {
	case AF_INET:
	    memset(&sa4, 0, sizeof(sa4));
	    sa4.sin_family = af;
	    sa4.sin_port = htons(port);
	    if (sourceip != NULL)
		sa4.sin_addr = ipv4;
	    sa = (struct sockaddr*)&sa4;
	    addrlen = sizeof(sa4);
	    break;
	case AF_INET6:
	    memset(&sa6, 0, sizeof(sa6));
	    sa6.sin6_family = af;
	    sa6.sin6_port = htons(port);
	    if (sourceip != NULL)
		sa6.sin6_addr = ipv6;
	    sa = (struct sockaddr*)&sa6;
	    addrlen = sizeof(sa6);
#ifdef SIN6_LEN
	    sa6.sin6_len = addrlen;
#endif
	    break;
    }
    if (bind(fd, sa, addrlen) < 0)
#else
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if(ip > 0) sa.sin_addr.s_addr = ip;
    if(bind(fd,(struct sockaddr*)&sa,sizeof(sa)) < 0)
#endif
    {
        close(fd);
        return -1;
    }

    /* start listening with a max accept queue of 10 */
    if(listen(fd, 10) < 0)
    {
        close(fd);
        return -1;
    }

    /* now set us up the bomb */
    if(mio_fd(m, fd, app, arg) < 0)
    {
        close(fd);
        return -1;
    }
    FD(m,fd).type = type_LISTEN;
    /* by default we read for new sockets */
    mio_read(m,fd);

    return fd;
}

/* create an fd and connect to the given ip/port */
int mio_connect(mio_t m, int port, char *hostip, mio_handler_t app, void *arg)
{
    int fd, flag, af = AF_INET;
#ifdef USE_IPV6
    struct in_addr ipv4;
    struct in6_addr ipv6;
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
    struct sockaddr* sa;
    socklen_t addrlen;
#else
    unsigned long int ip = 0;
    struct sockaddr_in sa;
#endif

    if(m == NULL || port <= 0 || hostip == NULL) return -1;

    mio_debug(ZONE, "mio connecting to %s:%d",hostip,port);

    /* convert the hostip */
#ifdef USE_IPV6
    if (inet_pton(AF_INET, hostip, &ipv4) > 0) {
	af = AF_INET;
    } else if (inet_pton(AF_INET6, hostip, &ipv6) > 0) {
	af = AF_INET6;
    } else {
	return -1;
    }
#else
    if((ip = inet_addr(hostip)) < 0) return -1;
#endif

    /* attempt to create a socket */
    if((fd = socket(af,SOCK_STREAM,0)) < 0) return -1;

    /* set the socket to non-blocking before connecting */
    flag =  fcntl(fd, F_GETFL, 0);
    flag |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flag);

    /* set up address info */
#ifdef USE_IPV6
    switch (af) {
	case AF_INET:
	    memset(&sa4, 0, sizeof(sa4));
	    sa4.sin_family = AF_INET;
	    sa4.sin_port = htons(port);
	    sa4.sin_addr = ipv4;
	    addrlen = sizeof(sa4);
	    sa = (struct sockaddr*)&sa4;
	    break;
	case AF_INET6:
	    memset(&sa6, 0, sizeof(sa6));
	    sa6.sin6_family = AF_INET6;
	    sa6.sin6_port = htons(port);
	    sa6.sin6_addr = ipv6;
	    addrlen = sizeof(sa6);
#ifdef SIN6_LEN
	    sa6.sin6_len = addrlen;
#endif
	    sa = (struct sockaddr*)&sa6;
	    break;
    }
#else
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = ip;
#endif

    /* try to connect */
#ifdef USE_IPV6
    flag = connect(fd,sa,addrlen);
#else
    flag = connect(fd,(struct sockaddr*)&sa,sizeof(sa));
#endif

    mio_debug(ZONE, "connect returned %d and %s", flag, strerror(errno));

    /* already connected?  great! */
    if(flag == 0 && mio_fd(m,fd,app,arg) == fd) return fd;

    /* gotta wait till later */
    if(flag == -1 && errno == EINPROGRESS && mio_fd(m,fd,app,arg) == fd)
    {
        mio_debug(ZONE, "connect processing non-blocking mode");

        FD(m,fd).type = type_CONNECT;
        MIO_SET_WRITE(m,fd);
        return fd;
    }

    /* bummer dude */
    close(fd);
    return -1;
}

