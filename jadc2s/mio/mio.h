#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <strings.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>

#ifndef INCL_MIO_H
#define INCL_MIO_H

/**
 * @file mio.h
 * @brief mio - manage i/o
 * 
 * This used to be something large and all inclusive for 1.2/1.4,
 * but for 1.5 and beyond it is the most simple fd wrapper possible.
 * It is also customized per-app and may be limited/extended depending on needs.
 * 
 * Usage is pretty simple:
 *  - create a manager
 *  - add fds or tell it to listen
 *  - assign an action handler
 *  - tell mio to read or write with a fd
 *  - process accept, read, write, and close requests
 * 
 * @note normal fd's don't get events unless the app calls mio_read/write() first!
 */

/**
 * the master mio mama, defined internally
 */
typedef struct mio_st *mio_t;

/**
 * these are the actions mio can signal to a handler
 */
typedef enum {
    action_ACCEPT,	/**< a connection has been accepted on this socket */
    action_READ,	/**< data can be read on this socket */
    action_WRITE,	/**< data can be written to this socket */
    action_CLOSE,	/**< the socket has been closed */
    action_IDLE		/**< the socket is idle */
} mio_action_t;

/**
 * handler function for actions on a fd
 *
 * @param m the mio that is signalling the action
 * @param a the action that is signalled
 * @param fd the fd on which the action happened
 * @param data action specific data
 * @param arg user provided argument at registering the callback
 * @return ?
 */
typedef int (*mio_handler_t) (mio_t m, mio_action_t a, int fd, const void* data, void *arg);

/**
 * create the mio subsystem
 *
 * @param maxfd maximum number of fds to handle
 * @return NULL on failure, pointer to new mio instance else
 */
mio_t mio_new(int maxfd);

/**
 * free a mio instance
 *
 * @param m the mio instance to free
 */
void mio_free(mio_t m);

/**
 * create a new listen socket in this mio
 *
 * @param m the mio to use
 * @param port listen on which port
 * @param sourceip listen on which IP address
 * @param app callback to use
 * @param arg what to pass to the arg argument of the mio_handler_t() function
 * @return <0 on failure, new fd else
 */
int mio_listen(mio_t m, int port, char *sourceip, mio_handler_t app, void *arg);

/**
 * create a new socket connected to this ip:port
 *
 * @note use mio_read()/mio_write() first
 *
 * @param m the mio to use
 * @param port connect to which port
 * @param hostip connect to which ip address
 * @param app callback function to use
 * @param arg what to pass to the arg argument of the mio_handler_t() function
 * @return new fd or <0
 */
int mio_connect(mio_t m, int port, char *hostip, mio_handler_t app, void *arg);

/**
 * tell mio to track this fd
 *
 * @param m the mio to use
 * @param fd the fd
 * @param app callback function to use
 * @param arg argument to pass to the callback function
 * @return new fd or <0 on failure
 */
int mio_fd(mio_t m, int fd, mio_handler_t app, void *arg);

/**
 * re-set the app handler
 *
 * @param m the mio to use
 * @param fd the fd for which the new callback should be set
 * @param app the new callback function to use
 * @param arg argument to pass to the callback function
 */
void mio_app(mio_t m, int fd, mio_handler_t app, void *arg);

/**
 * request that mio closes this fd
 *
 * @param m the mio to use
 * @param fd which fd to close
 */
void mio_close(mio_t m, int fd);

/**
 * mio should try the write action on this fd now
 *
 * @param m the mio to use
 * @param fd which fd to try the write action
 */
void mio_write(mio_t m, int fd);

/**
 * process read events for this fd
 *
 * @param m the mio to use
 * @param fd the fd
 */
void mio_read(mio_t m, int fd);

/**
 * give some cpu time to mio to check its sockets
 *
 * @param m the mio to use
 * @param timeout how many seconds mio should check its sockets, 0 is non-blocking
 */
void mio_run(mio_t m, int timeout);

#endif  /* INCL_MIO_H */

