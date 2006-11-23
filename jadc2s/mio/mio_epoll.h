#include <sys/epoll.h>

#define MIO_FUNCS \
    int _mio_fdop(int epfd, int fd, int op, __uint32_t events)          \
    {                                                                   \
        struct epoll_event ev;                                          \
        ev.events = events;                                             \
        ev.data.u64 = 0;                                                \
        ev.data.fd = fd;                                                \
        if ((epoll_ctl(epfd, op, fd, &ev)) != 0) {                      \
            mio_debug(ZONE, "epoll fdop %d on fd %d",op,fd);            \
            return -1;                                                  \
        }                                                               \
        return 0;                                                       \
    }                                                                   \
                                                                        \
    static int _mio_epoll(mio_t m, int t)                               \
    {                                                                   \
        return epoll_wait(m->epfd, m->events, m->maxfd, t*1000);        \
    }

#define MIO_VARS \
    int epfd; \
    struct epoll_event *events; \
    __uint32_t *evflags;

#define MIO_INIT_VARS(m) \
    do {                                                                \
        m->events = NULL;                                               \
        m->epfd = epoll_create(maxfd);                                  \
        if (m->epfd != -1) {                                            \
            mio_debug(ZONE, "epoll fd created: %d (size=%d)", m->epfd, maxfd); \
            m->events = malloc(sizeof(struct epoll_event) * (maxfd + 1));      \
            m->evflags = malloc(sizeof(__uint32_t) * (maxfd + 1));      \
        } else {                                                        \
            mio_debug(ZONE, "Can't epoll_create(%d).", maxfd);          \
            free(m->fds);                                               \
            free(m);                                                    \
            return NULL;                                                \
        }                                                               \
        memset(m->events, 0, sizeof(struct epoll_event) * (maxfd + 1)); \
        memset(m->evflags, 0, sizeof(__uint32_t) * (maxfd + 1));        \
    } while(0)

#define MIO_FREE_VARS(m)        free(m->events); close(m->epfd)

#define MIO_INIT_FD(m, pfd)     _mio_fdop(m->epfd, pfd, EPOLL_CTL_ADD, 0)

#define MIO_REMOVE_FD(m, pfd)   _mio_fdop(m->epfd, pfd, EPOLL_CTL_DEL, 0)

#define MIO_CHECK(m, t)         _mio_epoll(m, t)

#define MIO_SET_READ(m, fd)     _mio_fdop(m->epfd, fd, EPOLL_CTL_MOD, m->evflags[fd] |= EPOLLIN)
#define MIO_SET_WRITE(m, fd)    _mio_fdop(m->epfd, fd, EPOLL_CTL_MOD, m->evflags[fd] |= EPOLLOUT)

#define MIO_UNSET_READ(m, fd)   _mio_fdop(m->epfd, fd, EPOLL_CTL_MOD, m->evflags[fd] &= ~EPOLLIN)
#define MIO_UNSET_WRITE(m, fd)  _mio_fdop(m->epfd, fd, EPOLL_CTL_MOD, m->evflags[fd] &= ~EPOLLOUT)

#define MIO_CAN_READ(m, e)      m->events[e].events & (EPOLLIN|EPOLLHUP|EPOLLERR)
#define MIO_CAN_WRITE(m, e)     m->events[e].events & EPOLLOUT

#define MIO_ERROR(m)            errno
