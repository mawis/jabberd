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

/**
 * @file mio.cc
 * @brief MIO -- Managed Input/Output
 *
 * The purpose of this file, is mainly to provide support, to any component
 * of jabberd, for abstraced I/O functions.  This works much like tstreams,
 * and will incorporate the functionality of io_select initially, but will be
 * expanded to support any socket handling model, such as polld, SIGIO, etc
 *
 * This works to abstract the socket work, and hide it from the component,
 * this way, the component does not have to deal with any complexeties of
 * socket functions.
 */

#include <jabberd.h>

#include <errno.h>

/********************************************************
 *************  Internal MIO Functions  *****************
 ********************************************************/

/**
 * @brief internal structure holding data of the destination where we connect to
 */
typedef struct mio_connect_st {
    pool p;		/**< (memory-)pool to hold this data */
    char *ip;		/**< IP address where to connect to */
    int port;		/**< port where to connect to */
    mio_std_cb cb;	/**< callback function that should be notified on the new connection */
    void *cb_arg;	/**< argument that should be passed to the callback function */
    mio_handlers mh;	/**< mio internal handlers for different events, used to switch between raw and TLS-protected connections, XML streams or byte streams */
    pth_t t;		/**< thread for this connection */
    int connected;	/**< flag if the socket is connected */
} _connect_data,  *connect_data;

/* global object */
ios mio__data = NULL;	/**< global data for mio */
extern xmlnode greymatter__;

#ifdef WITH_IPV6
/**
 * compare two IPv6 or IPv4 addresses if they are in the same network
 *
 * @param addr1 the first address
 * @param addr2 the second address
 * @param netsize how many bits are in the network address
 * @return 1 if both addresses are in the same network, 0 if not
 */
static int _mio_compare_ipv6(const struct in6_addr *addr1, const struct in6_addr *addr2, int netsize) {
    int i;
    u_int8_t mask;

    if(netsize > 128)
	netsize = 128;

    for(i = 0; i < netsize/8; i++) {
	if(addr1->s6_addr[i] != addr2->s6_addr[i])
	    return 0;
    }

    if (netsize%8 == 0)
	return 1;

    mask = 0xff << (8 - netsize%8);

    return ((addr1->s6_addr[i]&mask) == (addr2->s6_addr[i]&mask));
}

/**
 * convert a netmask to an IPv6 network size
 *
 * If the netmask is NULL, 128 is returned.
 *
 * E.g. 255.255.255.0 is converted to 120 (the network is ::ffff:a.b.c.0 in this case)
 *
 * @param netmask string containing the netmask in traditional IPv4 notation
 * @return number of bits in the network part of the address (range 96...128, because the argument is IPv4)
 */
static int _mio_netmask_to_ipv6(const char *netmask) {
    struct in_addr addr;

    if (netmask == NULL) {
	return 128;
    }

    if (inet_pton(AF_INET, netmask, &addr)) {
	uint32_t temp = ntohl(addr.s_addr);
	int netmask = 128;

	while (netmask>96 && temp%2==0) {
	    netmask--;
	    temp /= 2;
	}
	return netmask;
    }

    return atoi(netmask);
}
#endif

/**
 * check if an IP address (IPv4 or IPv6) is allowed/forbidden to connect
 *
 * @param address the address that should be checked
 * @param check_allow 1 = check if it is allowed, 0 = check if it is forbidden
 * allow:
 * @return 1 if allowed by default, or IP inside an allowed network, 2 if explicitly allowed IP address, 0 if not allowed
 * deny:
 */
static int _mio_access_check(const char *address, int check_allow) {
    static xht namespaces = NULL;
#ifdef WITH_IPV6
    char temp_address[INET6_ADDRSTRLEN];
    char temp_ip[INET6_ADDRSTRLEN];
    static struct in_addr tmpa;
#endif

    pool temp_pool = pool_new();
   
    if (namespaces == NULL) {
	namespaces = xhash_new(2);
	xhash_put(namespaces, NULL, const_cast<char*>(NS_JABBERD_CONFIGFILE));
    }
    xmlnode io = xmlnode_get_list_item(xmlnode_get_tags(greymatter__, "io", namespaces, temp_pool), 0);
    xmlnode cur;

#ifdef WITH_IPV6
    if (inet_pton(AF_INET, address, &tmpa)) {
	strcpy(temp_address, "::ffff:");
	strcat(temp_address, address);
	address = temp_address;
    }
#endif

    if (xmlnode_get_list_item(xmlnode_get_tags(io, check_allow ? "allow" : "deny", namespaces, temp_pool), 0) == NULL) {
	pool_free(temp_pool);
        return check_allow ? 1 : 0; /* if there is no allow/deny section, allow all */
    }

    for (cur = xmlnode_get_firstchild(io); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
        char *ip, *netmask;
#ifdef WITH_IPV6
	struct in6_addr in_address, in_ip;
	int in_netmask;
#else
        struct in_addr in_address, in_ip, in_netmask;
#endif

        if (xmlnode_get_type(cur) != NTYPE_TAG)
            continue;

        if (j_strcmp(xmlnode_get_localname(cur), check_allow ? "allow" : "deny") != 0 || j_strcmp(xmlnode_get_namespace(cur), NS_JABBERD_CONFIGFILE) != 0) 
            continue;

	ip = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(cur, "ip", namespaces, temp_pool), 0));
	netmask = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(cur, "mask", namespaces, temp_pool), 0));

        if (ip == NULL)
            continue;

#ifdef WITH_IPV6
	if (inet_pton(AF_INET, ip, &tmpa)) {
	    strcpy(temp_ip, "::ffff:");
	    strcat(temp_ip, ip);
	    ip = temp_ip;
	}

	inet_pton(AF_INET6, address, &in_address);
#else
        inet_aton(address, &in_address);
#endif

        if (ip != NULL)
#ifdef WITH_IPV6
	    inet_pton(AF_INET6, ip, &in_ip);
#else
            inet_aton(ip, &in_ip);
#endif

        if (netmask != NULL) {
#ifdef WITH_IPV6
	    in_netmask = _mio_netmask_to_ipv6(netmask);

	    if(_mio_compare_ipv6(&in_address, &in_ip, in_netmask)) {
#else
            inet_aton(netmask, &in_netmask);
            if((in_address.s_addr & in_netmask.s_addr) == (in_ip.s_addr & in_netmask.s_addr)) {
#endif
		pool_free(temp_pool);
            	/* this ip is in the allow/deny network */
                return 1;
            }
        } else {
#ifdef WITH_IPV6
	    if (_mio_compare_ipv6(&in_ip, &in_address, 128))
#else
            if (in_ip.s_addr == in_address.s_addr)
#endif
		pool_free(temp_pool);
                return 2; /* exact matches hold greater weight */
        }
    }

    /* deny/allow the rest */
    pool_free(temp_pool);
    return 0;
}

/**
 * callback for Heartbeat, increments karma, and signals the
 * select loop, whenever a socket's punishment is over
 *
 * @param arg unused/ignored
 * @return always r_DONE
 */
static result _karma_heartbeat(void*arg) {
    mio cur;

    /* if there is nothing to do, just return */
    if (mio__data == NULL || mio__data->master__list == NULL) 
        return r_DONE;

    /* loop through the list, and add karma where appropriate */
    for (cur = mio__data->master__list; cur != NULL; cur = cur->next) {
        if (cur->k.dec != 0) {
	    /* Karma is enabled for this connection */
            int was_negative = 0;
            /* don't update if we are closing, or pre-initilized */
            if (cur->state == state_CLOSE) 
                continue;
     
            /* if we are being punished, set the flag */
            if (cur->k.val < 0) was_negative = 1; 
     
            /* possibly increment the karma */
            karma_increment( &cur->k );
     
            /* punishment is over */
            if (was_negative && cur->k.val >= 0)  {
               log_debug2(ZONE, LOGT_IO, "Punishment Over for socket %d: ", cur->fd);
	       /* we don't have to signal again, if a signal is pending */
	       if (mio__data->zzz_active <= 0) {
		   mio__data->zzz_active++;
		   pth_write(mio__data->zzz[1]," ",1);
	       }
            }
        }
    }

    /* always return r_DONE, to keep getting heartbeats */
    return r_DONE;
}

/** 
 * unlinks a socket from the master list 
 *
 * @param m socket that should be unlinked from mio__data->master__list
 */
static void _mio_unlink(mio m) {
    log_debug2(ZONE, LOGT_EXECFLOW, "Unlinking %X from master__list", m);

    if (mio__data == NULL) 
        return;

    if (mio__data->master__list == m)
       mio__data->master__list = mio__data->master__list->next;

    if (m->prev != NULL) 
        m->prev->next = m->next;

    if (m->next != NULL) 
        m->next->prev = m->prev;
}

/** 
 * links a socket to the master list
 *
 * The new socket is inserted as the first list element, but you must not rely on this.
 *
 * @param m socket that should be linked to mio__data->master__list
 */
static void _mio_link(mio m) {
    if (mio__data == NULL) 
        return;

    m->next = mio__data->master__list;
    m->prev = NULL;

    if (mio__data->master__list != NULL) 
        mio__data->master__list->prev = m;

    mio__data->master__list = m;
}

/** 
 * Dump this socket's write queue.
 *
 * Tries to write * as much of the write queue as it can, before the
 * write call would block the server
 *
 * @param m the connection that should get it's write queue dumped
 * @return -1 on error, 0 on success, and 1 if more data to write
 */
int _mio_write_dump(mio m) {
    int len = 0;
    mio_wbq cur = NULL;

    /* try to write as much as we can */
    while (m->queue != NULL) {
        cur = m->queue;

        log_debug2(ZONE, LOGT_IO, "write_dump writing data: %.*s", cur->len, cur->cur);

	/* try to write a queue item */
	len = (*m->mh->write)(m, cur->cur, cur->len);
	log_debug2(ZONE, LOGT_BYTES, "written %i of %i B on socket %i: %.*s", len, cur->len, m->fd, len, cur->cur);

	/* error? */
	if (len < 0) {
	    /* bounce the queue */
	    if (m->cb != NULL) {
		(*m->cb)(m, MIO_ERROR, m->cb_arg, NULL, NULL, 0);
	    }
	    return -1;
	}

	/* just nothing could be written? */
	if (len == 0) {
	    return 1;
	}

	/* not everything written? */
	if (len < cur->len) {
	    cur->cur = static_cast<char*>(cur->cur) + len;
	    cur->len -= len;
	    return 1;
	}

	/* we could write the entire node, kill it and try to write another */
	m->queue = m->queue->next;
	if (m->queue == NULL)
	    m->tail = NULL;
	pool_free(cur->p);
    } 
    return 0;
}

/** 
 * internal close function 
 * 
 * does a final write of the queue, bouncing and freeing all memory
 *
 * @param m the connection that gets closed
 */
static void _mio_close(mio m) {
    int ret = 0;
    xmlnode cur;

    /* ensure that the state is set to CLOSED */
    m->state = state_CLOSE;

    /* take it off the master__list */
    _mio_unlink(m);

    /* try to write what's in the queue */
    if (m->queue != NULL) 
        ret = _mio_write_dump(m);

    if (ret == 1) /* still more data, bounce it all */
        if (m->cb != NULL)
            (*m->cb)(m, MIO_ERROR, m->cb_arg, NULL, NULL, 0);

    /* notify of the close */
    if (m->cb != NULL)
        (*m->cb)(m, MIO_CLOSED, m->cb_arg, NULL, NULL, 0);

    /* close the socket, and free all memory */
    if (m->mh && m->mh->close)
	(*m->mh->close)(m, true);
    else
	close(m->fd);

    if (m->flags.rated) 
        jlimit_free(m->rate);

    pool_free(m->mh->p);

    /* cleanup the write queue */
    while ((cur = mio_cleanup(m)) != NULL)
        xmlnode_free(cur);

    pool_free(m->p);

    log_debug2(ZONE, LOGT_IO, "freed MIO socket");
}

/** 
 * accept an incoming connection from a listen sock
 *
 * @note accepting a connection has changed after jabberd 1.4.4! Until 1.4.4 we
 * had an accept handler for a socket. The accept handler to a non-encrypted
 * connection just accepted the connection. The handler for the OpenSSL encrypted
 * connection (typically on port 5223) accepted the connection and started the
 * SSL/TLS layer afterwards. As in any case we have to first accept the connection,
 * accepting is not done in a handler anymore, but in _mio_accept() itself.
 * After a new connection has been accepted, the accepted handler is called.
 * In case of a plain connection, this handler has to do nothing. In case of a
 * port 5223 connection, this handler can start the SSL/TLS layer. This also
 * cleans up the code of _mio_accept() where we had to copy values the _mio_ssl_accept
 * handler wrote to the ::mio passed to it, which was the mio of the listening socket
 * and not the structure for the new connection, which is created after the
 * accept handler had been called.
 *
 * @param m the socket on which we want to accept a connection
 * @return the new mio handle for the new connection
 */
static mio _mio_accept(mio m) {
#ifdef WITH_IPV6
    struct sockaddr_in6 serv_addr;
    char addr_str[INET6_ADDRSTRLEN];
#else
    struct sockaddr_in serv_addr;
#endif
    size_t addrlen = sizeof(serv_addr);
    int fd;
    int allow, deny;
    mio newm;

    log_debug2(ZONE, LOGT_IO, "_mio_accept calling accept on fd #%d", m->fd);

    /* pull a socket off the accept queue */
    fd = pth_accept(m->fd, (struct sockaddr*)&serv_addr, (socklen_t*)&addrlen);
    if (fd <= 0) {
	log_debug2(ZONE, LOGT_IO, "pth_accept() failed to accept on socket #%i", m->fd);
        return NULL;
    }

    /* do not accept a higher fd than FD_SET, or FD_CLR can handle */
    if (fd >= FD_SETSIZE) {
	log_warn(NULL, "could not accept incoming connection, maximum number of connections reached (%i)", FD_SETSIZE);
	close(fd);
	return NULL;
    }

    log_debug2(ZONE, LOGT_IO, "_mio_accept(%X) accepted fd #%d", m, fd);

    /* access and rate checks */
#ifdef WITH_IPV6
    allow = _mio_access_check(inet_ntop(AF_INET6, &serv_addr.sin6_addr, addr_str, sizeof(addr_str)), 1);
    deny  = _mio_access_check(addr_str, 0);

    if (deny >= allow) {
	log_warn("mio", "%s was denied access, due to the allow list of IPs", addr_str);
	close(fd);
	return NULL;
    }

    if (m->flags.rated && jlimit_check(m->rate, addr_str, 1)) {
	log_warn(NULL, "%s(%d) is being connection rate limited - the connection attempts from this IP exceed the rate limit defined in jabberd config", addr_str, fd);
        close(fd);
        return NULL;
    }

    log_debug2(ZONE, LOGT_IO, "new socket accepted (fd: %d, ip%s, port: %d)", fd, addr_str, ntohs(serv_addr.sin6_port));
#else /* IPv6 not enabled */
    allow = _mio_access_check(inet_ntoa(serv_addr.sin_addr), 1);
    deny  = _mio_access_check(inet_ntoa(serv_addr.sin_addr), 0);

    if (deny >= allow) {
        log_warn("mio", "%s was denied access, due to the allow list of IPs", inet_ntoa(serv_addr.sin_addr));
        close(fd);
        return NULL;
    }

    if (m->flags.rated && jlimit_check(m->rate, inet_ntoa(serv_addr.sin_addr), 1)) {
        log_warn(NULL, "%s(%d) is being connection rate limited - the connection attempts from this IP exceed the rate limit defined in jabberd config", inet_ntoa(serv_addr.sin_addr), fd);
        close(fd);
        return NULL;
    }

    log_debug2(ZONE, LOGT_IO, "new socket accepted (fd: %d, ip: %s, port: %d)", fd, inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port));
#endif

    /* create a new sock object for this connection */
    newm      = mio_new(fd, m->cb, m->cb_arg, mio_handlers_new(m->mh->read, m->mh->write, m->mh->parser));
#ifdef WITH_IPV6
    newm->peer_ip = pstrdup(newm->p, addr_str);
    newm->peer_port = ntohs(serv_addr.sin6_port);
#else
    newm->peer_ip = pstrdup(newm->p, inet_ntoa(serv_addr.sin_addr));
    newm->peer_port = ntohs(serv_addr.sin_port);
#endif
    newm->our_ip = pstrdup(newm->p, m->our_ip);

    /* copy karma settings */
    mio_karma2(newm, &m->k);

    /* is there an accepted handler? E.g. starting TLS layer at connection time if using Jabber over TLS on port 5223 */
    if (m->mh->accepted != NULL) {
	int ret = 0;

	ret = m->mh->accepted(newm);

	if (ret < 0) {
	    mio_close(m);
	    return newm;	/* return it to get it really closed and destroyed again */
	}
    }

    /* call the application callback, that wants to get notified for newly accepted sockets */
    if(m->cb != NULL);
        (*newm->cb)(newm, MIO_NEW, newm->cb_arg, NULL, NULL, 0);

    /* return the new mio */
    return newm;
}

/**
 * raise a signal on the connecting thread to time it out
 *
 * This callback is registered as a callback for connection sockets.
 *
 * @param arg ::connect_data for the connection
 * @return r_UNREG if the connection is now connected, r_DONE else
 */
static result _mio_connect_timeout(void *arg) {
    connect_data cd = (connect_data)arg;

    if(cd->connected) {
        pool_free(cd->p);
        return r_UNREG;
    }

    log_debug2(ZONE, LOGT_IO, "mio_connect taking too long connecting to %s, signaling to stop", cd->ip);
    if(cd->t != NULL)
        pth_raise(cd->t, SIGUSR2);

    return r_DONE; /* loop again */
}

/**
 * helper function for _mio_connect()
 */
static int _mio_connect_helper(mio m, struct sockaddr* serv_addr, socklen_t  addrlen) {
    sigset_t set;
    int sig;
    pth_event_t wevt;

    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);

    wevt = pth_event(PTH_EVENT_SIGS, &set, &sig);
    pth_fdmode(m->fd, PTH_FDMODE_BLOCK);
    return pth_connect_ev(m->fd, serv_addr, addrlen, wevt);
}

/**
 * helper-thread for mio_connect() to connect to a host
 *
 * @param arg ::connect_data for the connection
 */
static void* _mio_connect(void *arg) {
    connect_data	cd = (connect_data)arg;
#ifdef WITH_IPV6
    struct sockaddr_in6	sa;
    struct in6_addr	*saddr;
#else
    struct sockaddr_in	sa;
    struct in_addr*	saddr;
#endif
    int			flag = 1,
			flags;
    mio			newm;
    pool		p;
    sigset_t		set;
    static xht		namespaces = NULL;

    if (namespaces == NULL) {
	namespaces = xhash_new(3);
	xhash_put(namespaces, "", const_cast<char*>(NS_JABBERD_CONFIGFILE));
    }

    /* _mio_connect_timeout() is sending SIGUSR2 to signal a connect timeout */
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    pth_sigmask(SIG_BLOCK, &set, NULL);

    bzero((void*)&sa, sizeof(sa));

    /* create the new mio object, can't call mio_new.. don't want it in select yet */
    p           = pool_new();
    newm         = static_cast<mio>(pmalloco(p, sizeof(_mio)));
    newm->p      = p;
    newm->type   = type_NORMAL;
    newm->state  = state_ACTIVE;
    newm->peer_ip= pstrdup(p,cd->ip);
    newm->peer_port = cd->port;
    newm->cb     = cd->cb;
    newm->cb_arg = cd->cb_arg;
    mio_set_handlers(newm, cd->mh);

    /* create a socket to connect with */
#ifdef WITH_IPV6
    newm->fd = socket(PF_INET6, SOCK_STREAM,0);
#else
    newm->fd = socket(PF_INET, SOCK_STREAM,0);
#endif

    /* set socket options */
    if (newm->fd < 0 || setsockopt(newm->fd, SOL_SOCKET, SO_REUSEADDR, (char*)&flag, sizeof(flag)) < 0) {
	/* get the error message */
	newm->connect_errmsg = strerror(errno);
	
        if (cd->cb != NULL)
            (*cd->cb)(newm, MIO_CLOSED, cd->cb_arg, NULL, NULL, 0);
        cd->connected = -1;

        mio_handlers_free(newm->mh);
        if (newm->fd > 0)
            close(newm->fd);
        pool_free(p);
        return NULL;
    }

    /* optionally bind to a local address */
    pool temp_pool = pool_new();
    if (xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(greymatter__, "io/bind", namespaces, temp_pool), 0)) != NULL) {
#ifdef WITH_IPV6
	struct sockaddr_in6 sa;
	char *addr_str = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(greymatter__, "io/bind", namespaces, temp_pool), 0));
	char temp_addr[INET6_ADDRSTRLEN];
	struct in_addr tmp;

	if (inet_pton(AF_INET, addr_str, &tmp)) {
	    strcpy(temp_addr, "::ffff:");
	    strcat(temp_addr, addr_str);
	    addr_str = temp_addr;
	}

	sa.sin6_family = AF_INET6;
	sa.sin6_port = 0;
	sa.sin6_flowinfo = 0;

	inet_pton(AF_INET6, addr_str, &sa.sin6_addr);
#else
        struct sockaddr_in sa;
        sa.sin_family = AF_INET;
        sa.sin_port   = 0;
        inet_aton(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(greymatter__, "io/bind", namespaces, temp_pool), 0)), &sa.sin_addr);
#endif
        bind(newm->fd, (struct sockaddr*)&sa, sizeof(sa));
    }
    pool_free(temp_pool);
    temp_pool = NULL;

    /* parse the IP to connect to */
#ifdef WITH_IPV6
    saddr = make_addr_ipv6(cd->ip);
#else
    saddr = make_addr(cd->ip);
#endif
    if (saddr == NULL) {
	newm->connect_errmsg = "Could not resolve hostname or parse IP address";
        if (cd->cb != NULL)
            (*cd->cb)(newm, MIO_CLOSED, cd->cb_arg, NULL, NULL, 0);
        cd->connected = -1;

        mio_handlers_free(newm->mh);
        if (newm->fd > 0)
            close(newm->fd);
        pool_free(p);
        return NULL;
    }

#ifdef WITH_IPV6
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(cd->port);
    sa.sin6_addr = *saddr;
#else
    sa.sin_family = AF_INET;
    sa.sin_port = htons(cd->port);
    sa.sin_addr.s_addr = saddr->s_addr;
#endif

    log_debug2(ZONE, LOGT_IO, "calling the connect handler for mio object %X", newm);
    if (_mio_connect_helper(newm, (struct sockaddr*)&sa, sizeof sa) < 0) {
	/* get the error message */
	newm->connect_errmsg = strerror(errno);

        if (cd->cb != NULL)
            (*cd->cb)(newm, MIO_CLOSED, cd->cb_arg, NULL, NULL, 0);
        cd->connected = -1;

        if (newm->fd > 0)
            close(newm->fd);
        mio_handlers_free(newm->mh);
        pool_free(p);
        return NULL;
    }

    newm->connect_errmsg = "";

    /* set the socket to non-blocking */
    flags =  fcntl(newm->fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(newm->fd, F_SETFL, flags);

    /* XXX pthreads race condition.. cd->connected may be checked in the timeout, and cd freed before these calls */

    /* set the default karma values */
    mio_karma2(newm, mio__data->k);
    
    /* add to the select loop */
    _mio_link(newm);
    cd->connected = 1; 

    /* notify the select loop */
    if (mio__data != NULL) {
	/* we don't have to send multiple signals */
	if (mio__data->zzz_active <= 0) {
	    mio__data->zzz_active++;
	    pth_write(mio__data->zzz[1]," ",1);
	}
    }

    /* notify the client that the socket is born */
    if (newm->cb != NULL)
        (*newm->cb)(newm, MIO_NEW, newm->cb_arg, NULL, NULL, 0);

    return NULL;
}

/**
 * read data from a socket
 *
 * @param m the ::mio to read from
 */
static void _mio_read_from_socket(mio m) {
    char buf[8192]; /* max socket read buffer */
    size_t maxlen = 0;
    ssize_t len = 0;

    do {
	maxlen = KARMA_READ_MAX(m->k.val);

	/* do not read more than the buffer is big */
	if (maxlen > sizeof(buf)-1)
	    maxlen = sizeof(buf)-1;

	/* read from the socket */
	len = (*(m->mh->read))(m, buf, maxlen);
	log_debug2(ZONE, LOGT_BYTES, "IN (%i of max %i, fd#%i): %.*s", len, maxlen, m->fd, len, buf);

	/* error? no more data to read? */
	if (len < 0) {
	    /* error or socket close */
	    mio_close(m);
	    return;
	} else if (len == 0) {
	    /* no more data to read (but connection still there) */
	    return;
	}

	/* we have received data, update karma */
	if (m->k.dec != 0) {
	    /* karma is enabled */
	    karma_decrement(&m->k, len);
	}

	/* terminate buffer with 0 byte - and print dump when in debug mode */
	buf[len] = '\0';
	log_debug2(ZONE, LOGT_IO, "read on socket %d: %.*s", m->fd, len, buf);

	/* pass on the data we read */
	(*m->mh->parser)(m, buf, len);

    } while (len == maxlen);
}

/**
 * helper function for _mio_loop_process_a_socket, that recalls the handshake function
 *
 * @param m mio on which the handshake function should be recalled
 */
static void _mio_do_handshake(mio m) {
    int handshake_ret = 0;

    /* sanity checks */
    if (m == NULL) {
	return;
    }
    if (m->mh == NULL || m->mh->handshake == NULL) {
	m->flags.recall_handshake_when_readable = 0;
	m->flags.recall_handshake_when_writeable = 0;
	return;
    }

    /* recall the handshake function */
    handshake_ret = m->mh->handshake(m);
    if (handshake_ret < 0) {
	mio_close(m);
    }

    /* handshake finished now? */
    if (!m->flags.recall_handshake_when_readable && !m->flags.recall_handshake_when_writeable) {
	log_debug2(ZONE, LOGT_IO, "handshake for socket %i has finished", m->fd);
    }
}

/**
 * helper function to process a single socket inside the mio select() loop
 *
 * Steps:
 * - Karma handling
 * - Doing handshaking (TLS handshake)
 * - Reading from sockets
 * - Writing to sockets
 *
 * If one of these steps fails, the processing of this socket is stopped and the function returns
 *
 * @param cur the mio that should be processed
 * @param maxfd the maximum file descriptor (gets updated by this function)
 * @param rfds sockets that had read events
 * @param wfds sockets that had write events
 * @param select_retval the return value of the last pth_select() call
 */
static void _mio_loop_process_a_socket(mio m, int *maxfd, fd_set *rfds, fd_set *wfds, int select_retval) {

    log_debug2(ZONE, LOGT_IO, "processing mio %X (state %i)", m, m->state);

    /* find the max fd: during a full interation on the master__list we always update maxfd as long as we find a higher fd  */
    if (m->fd > *maxfd)
	*maxfd = m->fd;

    /* pause while the rest of jabberd catches up */
    pth_yield(NULL);

    /* we cannot continue processing this socket, if pth_select() failed */
    if (select_retval == -1) {
	return;
    }

    /* listening sockets are a bit different, we only check for new connections */
    if (m->type == type_LISTEN) {
	if (FD_ISSET(m->fd, rfds)) {
	    mio accepted_m = _mio_accept(m);

	    log_debug2(ZONE, LOGT_IO, "Accepted socket on MIO object %X, fd %i", accepted_m, accepted_m != NULL ? accepted_m->fd : -1);

	    if(accepted_m != NULL) {
		if(accepted_m->fd > *maxfd)
		    *maxfd=accepted_m->fd;
	    }
	}
	return;
    }

    /* handle recall-flags */
    if (m->flags.recall_write_when_writeable) {
	int write_return = 0;

	if (!FD_ISSET(m->fd, wfds)) {
	    log_debug2(ZONE, LOGT_IO, "socket %i waits to become writeable again ...", m->fd);
	    return;
	}

	/* re-call write */
	write_return = _mio_write_dump(m);
	if (write_return < 0) {
	    mio_close(m);
	}
	return;
    }
    if (m->flags.recall_write_when_readable) {
	int write_return = 0;

	if (!FD_ISSET(m->fd, rfds)) {
	    log_debug2(ZONE, LOGT_IO, "socket %i waits to become readable again for being able to write ...", m->fd);
	    return;
	}

	/* re-call write */
	write_return = _mio_write_dump(m);
	if (write_return < 0) {
	    mio_close(m);
	}
	return;
    }
    if (m->flags.recall_read_when_writeable) {
	if (!FD_ISSET(m->fd, wfds)) {
	    log_debug2(ZONE, LOGT_IO, "socket %i waits to become writeable again for being able to read ...", m->fd);
	    return;
	}

	/* re-call read */
	_mio_read_from_socket(m);
	return;
    }
    if (m->flags.recall_read_when_readable) {
	if (!FD_ISSET(m->fd, rfds)) {
	    log_debug2(ZONE, LOGT_IO, "socket %i waits to become readable again ...", m->fd);
	    return;
	}

	/* re-call read */
	_mio_read_from_socket(m);
	return;
    }
    if (m->flags.recall_handshake_when_writeable) {
	if (!FD_ISSET(m->fd, wfds)) {
	    log_debug2(ZONE, LOGT_IO, "socket %i waits to become writeable again for being able to handshake ...", m->fd);
	    return;
	}

	/* re-call handshake */
	_mio_do_handshake(m);
	return;
    }
    if (m->flags.recall_handshake_when_readable) {
	if (!FD_ISSET(m->fd, rfds)) {
	    log_debug2(ZONE, LOGT_IO, "socket %i waits to become readable again for being able to handshake ...", m->fd);
	    return;
	}

	/* re-call handshake */
	_mio_do_handshake(m);
	return;
    }

    /* no outstanding recalls */

    /* anything to read? */
    if (FD_ISSET(m->fd, rfds)) {
	log_debug2(ZONE, LOGT_IO, "Trying to read on socket %i", m->fd);
	_mio_read_from_socket(m);
    }

    /* closed in the meantime? */
    if (m->state == state_CLOSE) {
	return;
    }

    /* try to write */
    if (FD_ISSET(m->fd, wfds)) {
	int write_return = 0;
	write_return = _mio_write_dump(m);

	if (write_return < 0) {
	    mio_close(m);
	}
    }
}

/** 
 * main select loop thread 
 *
 * @param arg unused/ignored
 */
static void* _mio_main(void *arg) {
    fd_set      wfds;       /* fd set containing fds that should be checked for/had a write event */
    fd_set      rfds;       /* fd set containing fds that should be checked for/had a write event */
    mio         cur = NULL,
		next = NULL;
    char        buf[8192]; /* max socket read buffer      */
    int         retval,
                maxfd=0;
    static xht	namespaces = NULL;

    if (namespaces == NULL) {
	namespaces = xhash_new(3);
	xhash_put(namespaces, "", const_cast<char*>(NS_JABBERD_CONFIGFILE));
    }

    log_debug2(ZONE, LOGT_INIT, "MIO is starting up");

    /* init the socket junk */
    maxfd = mio__data->zzz[0];

    /* loop forever -- will only exit when mio__data->master__list is NULL and mio__data->shutdown is 1*/
    while (1) {
        log_debug2(ZONE, LOGT_EXECFLOW, "mio while loop top");

        /* if we are closing down, exit the loop */
        if (mio__data->shutdown == 1 && mio__data->master__list == NULL)
            break;

	/* init the sockets we want to check */
	FD_ZERO(&wfds);
	FD_ZERO(&rfds);
        for (cur = mio__data->master__list; cur != NULL; cur = cur->next) {
	    /* check if we want to get write events for this socket */
            if (cur->queue != NULL || cur->flags.recall_write_when_writeable || cur->flags.recall_read_when_writeable || cur->flags.recall_handshake_when_writeable)
		FD_SET(cur->fd, &wfds);

	    /* check if we want to get read events for this socket */
	    if (cur->k.val > 0 || cur->flags.recall_write_when_readable || cur->flags.recall_read_when_readable || cur->flags.recall_handshake_when_readable)
		FD_SET(cur->fd, &rfds);
	}

        /* wait for a socket event */
        FD_SET(mio__data->zzz[0],&rfds); /* include our wakeup socket */
        retval = pth_select(maxfd+1, &rfds, &wfds, NULL, NULL);
        /* if retval is -1, fd sets are undefined across all platforms */

        log_debug2(ZONE, LOGT_EXECFLOW, "mio while loop, working");

        /* reset maxfd, in case it changes (more updates in _mio_loop_process_a_socket() is it's updated when pth_select is called again) */
        maxfd=mio__data->zzz[0];

        /* check our zzz */
        if (FD_ISSET(mio__data->zzz[0],&rfds)) {
	    log_debug2(ZONE, LOGT_EXECFLOW, "got a notify on zzz");
            pth_read(mio__data->zzz[0], buf, sizeof(buf));
	    mio__data->zzz_active = 0;
        }

        /* loop through the sockets, check for stuff to do */
        for (cur = mio__data->master__list; cur != NULL; cur = next) {
	    next = cur->next;		/* a mio might get deleted inside _mio_loop_process_a_socket() so that we cannot access cur afterwards! */
	    /* if the mio socket is not closed, process it */
	    if (cur->state != state_CLOSE) {
		_mio_loop_process_a_socket(cur, &maxfd, &rfds, &wfds, retval);
	    }
	    /* if the mio socket is closed, close it on the socket layer */
	    if (cur->state == state_CLOSE) {
		_mio_close(cur);
	    }
	}
    }
}

/***************************************************\
*      E X T E R N A L   F U N C T I O N S          *
\***************************************************/

/**
 * Initialize manged I/O handling
 *
 * This must be called before MIO is used
 */
void mio_init(void) {
    pool p;
    pth_attr_t attr;
    xmlnode io = NULL;
    xmlnode karma = NULL;
    xmlnode tls = NULL;
    xht namespaces = NULL;

    namespaces = xhash_new(3);
    pool temp_pool = pool_new();
    xhash_put(namespaces, "", const_cast<char*>(NS_JABBERD_CONFIGFILE));
    io = xmlnode_get_list_item(xmlnode_get_tags(greymatter__, "io", namespaces, temp_pool), 0);
    karma = xmlnode_get_list_item(xmlnode_get_tags(io, "karma", namespaces, temp_pool), 0);

    tls = xmlnode_get_list_item(xmlnode_get_tags(io, "tls", namespaces, temp_pool), 0);
    if (tls == NULL) {
	tls = xmlnode_get_list_item(xmlnode_get_tags(io, "ssl", namespaces, temp_pool) ,0);
	if (tls != NULL) {
	    log_warn(NULL, "Please update your configuration. The <ssl/> elements have been renamed to <tls/>. Falling back to use <ssl/> for now: %s", xmlnode_serialize_string(tls, xmppd::ns_decl_list(), 0));
	}
    }
    if (tls != NULL) {
        mio_ssl_init(tls);
    }

    if (mio__data == NULL) {
        register_beat(KARMA_HEARTBEAT, _karma_heartbeat, NULL);

        /* malloc our instance object */
        p            = pool_new();
        mio__data    = static_cast<ios>(pmalloco(p, sizeof(_ios)));
        mio__data->p = p;
        mio__data->k = karma_new(p);
        pipe(mio__data->zzz);

        /* start main accept/read/write thread */
        attr = pth_attr_new();
        pth_attr_set(attr,PTH_ATTR_JOINABLE,FALSE);
#ifdef __CYGWIN__
        pth_attr_set(attr,PTH_ATTR_STACK_SIZE, 128*1024);
#endif
        mio__data->t=pth_spawn(attr, _mio_main, NULL);
        pth_attr_destroy(attr);

        /* give time to init the signal handlers */
        pth_yield(NULL);
    }

    /* where to bounce HTTP requests to */
    mio__data->bounce_uri = pstrdup(mio__data->p, xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(io, "bounce", namespaces, temp_pool), 0)));

    if (karma != NULL) {
        mio__data->k->val	  = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(karma, "init", namespaces, temp_pool), 0)), KARMA_INIT);
        mio__data->k->max         = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(karma, "max", namespaces, temp_pool), 0)), KARMA_MAX);
        mio__data->k->inc         = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(karma, "inc", namespaces, temp_pool), 0)), KARMA_INC);
        mio__data->k->dec         = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(karma, "dec", namespaces, temp_pool), 0)), KARMA_DEC);
        mio__data->k->penalty     = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(karma, "penalty", namespaces, temp_pool), 0)), KARMA_PENALTY);
        mio__data->k->restore     = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(karma, "restore", namespaces, temp_pool), 0)), KARMA_RESTORE);
        mio__data->k->reset_meter = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(karma, "resetmeter", namespaces, temp_pool), 0)), KARMA_RESETMETER);
    }
    mio__data->rate_t        = j_atoi(xmlnode_get_attrib_ns(xmlnode_get_list_item(xmlnode_get_tags(io, "rate", namespaces, temp_pool), 0), "time", NULL), 0);
    mio__data->rate_p        = j_atoi(xmlnode_get_attrib_ns(xmlnode_get_list_item(xmlnode_get_tags(io, "rate", namespaces, temp_pool), 0), "points", NULL), 0);

    pool_free(temp_pool);
    xhash_free(namespaces);
}

/**
 * Cleanup function when server is shutting down, closes
 * all sockets, so that everything can be cleaned up
 * properly.
 */
void mio_stop(void) {
    mio cur, mnext;

    log_debug2(ZONE, LOGT_CLEANUP, "MIO is shutting down");

    /* no need to do anything if mio__data hasn't been used yet */
    if (mio__data == NULL) 
        return;

    /* flag that it is okay to exit the loop */
    mio__data->shutdown = 1;

    /* loop each socket, and close it */
    for (cur = mio__data->master__list; cur != NULL;) {
        mnext = cur->next;
        _mio_close(cur);
    	cur = mnext;
    }

    /* signal the loop to end */
    pth_abort(mio__data->t);

    pool_free(mio__data->p);
    mio__data = NULL;
}

/**
 * creates a new mio object from a file descriptor
 *
 * @param fd the file descriptor the caller already has
 * @param cb the callback function, MIO should call on events
 * @param arg the argument MIO should pass to the callback function, when calling it
 * @param mh which ::mio_handlers MIO should use for this connection
 * @return pointer to the new MIO object, NULL on failure
 */
mio mio_new(int fd, mio_std_cb cb, void *arg, mio_handlers mh) {
    mio   newm    =  NULL;
    pool  p      =  NULL;
    int   flags  =  0;

    if (fd <= 0) 
        return NULL;
    
    /* create the new MIO object */
    p           = pool_new();
    newm         = static_cast<mio>(pmalloco(p, sizeof(_mio)));
    newm->p      = p;
    newm->type   = type_NORMAL;
    newm->state  = state_ACTIVE;
    newm->fd     = fd;
    newm->cb     = cb;
    newm->cb_arg = arg;
    mio_set_handlers(newm, mh);

    /* set the default karma values */
    mio_karma2(newm, mio__data->k);
    mio_rate(newm, mio__data->rate_t, mio__data->rate_p);
    
    /* set the socket to non-blocking */
    flags =  fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);

    /* add to the select loop */
    _mio_link(newm);

    /* notify the select loop */
    if (mio__data != NULL) {
	log_debug2(ZONE, LOGT_EXECFLOW, "sending zzz notify to the select loop in mio_new()");
	/* if there has been already sent a signal, that is not yet processed, we don't
	 * have to send this signal twice. Else we could get blocking here at the write() call
	 * if we send really many signals, what seems to be possible for large rosters as
	 * reported by Marco Balmer. I have not really tried to reproduce this, but it seems
	 * logical and I don't see where it can hurt to send only one signal.
	 * I have also considered using pth_write() here, but as I remember, there was a reason
	 * why a real write is used here. It would be really nice, if pth would be documented
	 * better ... and it would be even nicer not to use pth at all ...
	 */
	if (mio__data->zzz_active <= 0) {
	    mio__data->zzz_active++;
	    write(mio__data->zzz[1]," ",1);
	    log_debug2(ZONE, LOGT_EXECFLOW, "notify sent");
	}
    }

    return newm;
}

/**
 * resets the callback function
 *
 * @param m the mio to update the callback function for
 * @param cb the new callback function
 * @param arg the new argument MIO should pass to the callback function
 */
void mio_reset(mio m, mio_std_cb cb, void *arg) {
    if (m == NULL) 
        return;

    m->cb     = cb;
    m->cb_arg = arg;
}

/**
 * client call to close the socket
 *
 * @param m the socket, that should be closed
 */
void mio_close(mio m) {
    if (m == NULL) 
        return;

    m->state = state_CLOSE;
    if (mio__data != NULL) {
	log_debug2(ZONE, LOGT_EXECFLOW, "sending zzz notify to the select loop in mio_close()");
	/* there needs to be only one pending signal */
	if (mio__data->zzz_active <= 0) {
	    mio__data->zzz_active++;
	    write(mio__data->zzz[1]," ",1);
	    log_debug2(ZONE, LOGT_EXECFLOW, "notify sent");
	}
    }
}

/** 
 * writes a str, or XML stanza to the client socket
 *
 * You can only write the xmlnode OR the buffer to the mio. If the buffer argument is not equal to NULL,
 * the buffer is used and the xmlnode is ignored.
 *
 * @param m the ::mio to write the data to
 * @param stanza ::xmlnode containing the stanza, that should be written to a stream (gets freed after the data has been written)
 * @param buffer pointer to a buffer of characters, that should be written to the connection
 * @param len number of bytes contained in the buffer, that should be written (-1 to write a zero terminated string contained in the buffer)
 */
void mio_write(mio m, xmlnode stanza, char *buffer, int len) {
    mio_wbq newwbq;
    pool p;

    if (m == NULL) 
        return;

    /* if there is nothing to write */
    if (stanza == NULL && buffer == NULL) {
        log_debug2("mio", LOGT_IO|LOGT_STRANGE, "[%s] mio_write called without x or buffer", ZONE);
        return;
    }

    /* create the pool for this wbq */
    if (stanza != NULL)
        p = xmlnode_pool(stanza);
    else
        p = pool_new();

    /* create the wbq */
    newwbq    = static_cast<mio_wbq>(pmalloco(p, sizeof(_mio_wbq)));
    newwbq->p = p;

    /* set the queue item type */
    if (buffer != NULL) {
        newwbq->type = queue_CDATA;

        if (len == -1)
            len = strlen(buffer);

        /* XXX more hackish code to print the stream header right on a NUL xmlnode socket */
        if (m->type == type_NUL && strncmp(buffer,"<?xml ",6) == 0) {
            newwbq->data = pmalloco(p,len+2);
            memcpy(newwbq->data,buffer,len);
            memcpy((static_cast<char*>(newwbq->data) + len) - 1, "/>",3);
            len++;
        } else {
            newwbq->data = pmalloco(p,len+1);
            memcpy(newwbq->data,buffer,len);
        }
    } else {
        newwbq->type = queue_XMLNODE;

	newwbq->data = xmlnode_serialize_string(stanza, m->out_ns ? *m->out_ns : xmppd::ns_decl_list(), 0);
	if (!newwbq->data) {
	    pool_free(p);
	    return;
	}

        len = strlen(static_cast<char*>(newwbq->data));
    }

    /* include the \0 if we're special */
    if (m->type == type_NUL) {
        len++;
    }

    /* assign values */
    newwbq->x    = stanza;
    newwbq->cur  = newwbq->data;

    newwbq->len = len;

    /* put at end of queue */
    if (m->tail == NULL)
        m->queue = newwbq;
    else
        m->tail->next = newwbq;
    m->tail = newwbq;

    log_debug2(ZONE, LOGT_IO, "mio_write called on stanza: %X buffer: %.*s", stanza, len, buffer);
    /* notify the select loop that a packet needs writing */
    if (mio__data != NULL) {
	log_debug2(ZONE, LOGT_EXECFLOW, "sending zzz notify to the select loop in mio_write()");
	/* there only needs to be one pending signal */
	if (mio__data->zzz_active <= 0) {
	    mio__data->zzz_active++;
	    write(mio__data->zzz[1]," ",1);
	    log_debug2(ZONE, LOGT_EXECFLOW, "notify sent");
	}
    }
}

/**
 * write the start tag for the root element to a stream
 *
 * @param m the mio of the stream where to write the start tag for the root element to
 * @param root the root element (freed by this function)
 * @param stream_type type of stream: 0 for 'jabber:server', 1 for 'jabber:client', 2 for 'jabber:component:accept'
 */
void mio_write_root(mio m, xmlnode root, int stream_type) {
    char *serialized_root = NULL;

    serialized_root = xstream_header_char(root, stream_type);
    mio_write(m, NULL, serialized_root, -1);

    /* remember namespaces */
    m->out_ns = new xmppd::ns_decl_list();

    // xstream_header_char() might have added declarations for the default namespace as well as for the namespace defined by the db prefix
    char const* default_namespace = xmlnode_get_attrib_ns(root, "xmlns", NS_XMLNS);
    if (default_namespace) {
	// we do handle NS_CLIENT and NS_COMPONENT_ACCEPT as NS_SERVER internally
	if (default_namespace == NS_CLIENT || default_namespace == NS_COMPONENT_ACCEPT)
	    default_namespace = NS_SERVER;

	m->out_ns->update("", default_namespace);
    }
    char const* db_namespace = xmlnode_get_attrib_ns(root, "db", NS_XMLNS);
    if (db_namespace) {
	m->out_ns->update("db", db_namespace);
    }

    xmlnode_free(root);
}

/**
 * sets karma values
 */
void mio_karma(mio m, int val, int max, int inc, int dec, int penalty, int restore) {
    if (m == NULL)
       return;

    m->k.val     = val;
    m->k.max     = max;
    m->k.inc     = inc;
    m->k.dec     = dec;
    m->k.penalty = penalty;
    m->k.restore = restore;
}

/**
 * copy karma to a mio socket
 *
 * @param m the mio to copy the karma to
 * @param k the karma to copy to the mio
 */
void mio_karma2(mio m, struct karma *k) {
    if (m == NULL)
       return;

    karma_copy(&m->k, k);
}

/**
 * sets connection rate limits
 */
void mio_rate(mio m, int rate_time, int max_points) {
    if (m == NULL || rate_time == 0) 
        return;

    m->flags.rated = 1;
    if (m->rate != NULL)
        jlimit_free(m->rate);

    m->rate = jlimit_new(rate_time, max_points);
}

/**
 * pops the last xmlnode from the queue
 *
 * This function removes the last xmlnode from a write queue. This is normally used to get unsent stanzas
 * from the queue in case of an error happens and the stanzas cannot be delivered.
 *
 * The returned xmlnodes have to be freed by the caller.
 *
 * Elements in the write queue, that have no xmlnode attached, but are just character data are
 * deleted by this function and the memory associated with these items is freed by mio_cleanup().
 *
 * @param m the mio stream to get the last xmlnode stanza in the write queue for.
 * @return last stanza item in the write queue (has to be freed by the caller), or NULL if no further stanzas
 */
xmlnode mio_cleanup(mio m) {
    mio_wbq     cur;
    
    if (m == NULL || m->queue == NULL) 
        return NULL;

    /* find the first queue item with a xmlnode attached */
    for (cur = m->queue; cur != NULL;) {

        /* move the queue up */
        m->queue = cur->next;

        /* set the tail pointer if needed */
        if (m->queue == NULL)
            m->tail = NULL;

        /* if there is no node attached */
        if (cur->x == NULL) {
            /* just kill this item, and move on..
             * only pop xmlnodes 
             */
            mio_wbq next = m->queue;
            pool_free(cur->p);
            cur = next;
            continue;
        }

        /* and pop this xmlnode */
        return cur->x;
    }

    /* no xmlnodes found */
    return NULL;
}

/** 
 * request to connect to a remote host 
 *
 * @param host the host where to connect to (either a IPv4 or IPv6)
 * @param port the port number to connect to
 * @param cb the application callback function
 * @param cb_arg argument to pass to the application callback function
 * @param timeout how long to wait for a connection to be established (0 for using the default value)
 * @param mh the ::mio_handlers used to select the desired type of socket (e.g. an XML stream or a TLS protected socket)
 */
void mio_connect(char *host, int port, mio_std_cb cb, void *cb_arg, int timeout, mio_handlers mh) {
    connect_data cd = NULL;
    pool         p  = NULL;
    pth_attr_t   attr;

    /* verify data */
    if (host == NULL || port == 0) 
        return;

    if (timeout <= 0)
        timeout = 30; /* default timeout */

    if (mh == NULL)
        mh = mio_handlers_new(NULL, NULL, NULL);

    /* create the connect struct */
    p          = pool_new();
    cd         = static_cast<connect_data>(pmalloco(p, sizeof(_connect_data)));
    cd->p      = p;
    cd->ip     = pstrdup(p, host);
    cd->port   = port;
    cd->cb     = cb;
    cd->cb_arg = cb_arg;
    cd->mh     = mh;

#ifdef WITH_IPV6
    if(!strchr(host,':')) {
	char *temp = static_cast<char*>(pmalloco(p, strlen(host)+8));
	strcpy(temp, "::ffff:");
	strcat(temp, host);
	host = temp;
    }
#endif

    attr = pth_attr_new();
    pth_attr_set(attr,PTH_ATTR_JOINABLE,FALSE);
    cd->t      = pth_spawn(attr, _mio_connect, (void*)cd);
    pth_attr_destroy(attr);

    register_beat(timeout, _mio_connect_timeout, (void*)cd);
}

/**
 * call to start listening with select 
 * 
 * @param port port to listen at
 * @param listen_host IPv4 or IPv6 address to listen at
 * @param cb application callback function
 * @param arg argument to pass to the application callback function
 * @param mh ::mio_handlers used for this connection
 * @return the listening mio object that has been created, NULL on failure
 */
mio mio_listen(int port, const char *listen_host, mio_std_cb cb, void *arg, mio_handlers mh) {
    mio        newm;
    int        fd;

    if (mh == NULL)
        mh = mio_handlers_new(NULL, NULL, NULL);

    log_debug2(ZONE, LOGT_IO, "mio to listen on %d [%s]",port, listen_host);

    /* attempt to open a listening socket */
    fd = make_netsocket(port, listen_host, NETSOCKET_SERVER);

    /* if we got a bad fd we can't listen */
    if (fd < 0) {
        log_alert(NULL, "mio unable to listen on %d [%s]: jabberd already running or invalid interface?", port, listen_host);
        return NULL;
    }

    /* start listening with a max accept queue of 10 */
    if (listen(fd, 10) < 0) {
        log_alert(NULL, "mio unable to listen on %d [%s]: jabberd already running or invalid interface?", port, listen_host);
        return NULL;
    }

    /* create the sock object, and assign the values */
    newm       = static_cast<mio>(mio_new(fd, cb, arg, mh));
    newm->type = type_LISTEN;
    newm->our_ip = pstrdup(newm->p, listen_host);

    log_debug2(ZONE, LOGT_IO, "mio starting to listen on %d [%s]", port, listen_host);

    return newm;
}

/**
 * create a ::mio_handlers instance, that can be passed to mio_listen() or mio_accept()
 *
 * The ::mio_handlers can be used to setup different 'types' of sockets
 *
 * Default is to have an unencrypted socket reading plain bytes.
 *
 * If you are requesting a TLS protected socket (using ::MIO_SSL_READ and ::MIO_SSL_WRITE),
 * you also have to modify the accepted function in the returned ::mio_handlers afterwards!
 *
 * @param rf handler used for reading, NULL for default (may be ::MIO_RAW_READ or ::MIO_SSL_READ)
 * @param wf handler used for writing, NULL for default (may be ::MIO_RAW_WRITE or ::MIO_SSL_WRITE)
 * @param pf handler used for parsing, NULL for default (may be ::MIO_RAW_PARSER or ::MIO_XML_PARSER)
 * @return new instance of ::mio_handlers
 */
mio_handlers mio_handlers_new(mio_read_func rf, mio_write_func wf, mio_parser_func pf) {
    pool p = pool_new();
    mio_handlers newh;

    newh = static_cast<mio_handlers>(pmalloco(p, sizeof(_mio_handlers)));

    newh->p = p;

    /* yay! a chance to use the tertiary operator! */
    newh->read   = rf ? rf : MIO_RAW_READ;
    newh->write  = wf ? wf : MIO_RAW_WRITE;
    newh->parser = pf ? pf : MIO_RAW_PARSER;

    return newh;
}

/**
 * free a ::mio_handlers structure
 *
 * @param mh the ::mio_handlers structure that should be freed
 */
void mio_handlers_free(mio_handlers mh) {
    if (mh == NULL)
        return;

    pool_free(mh->p);
}

/**
 * reset the handlers of a ::mio structure
 *
 * @param m the mio to set the handlers for
 * @param mh the new handlers to set
 */
void mio_set_handlers(mio m, mio_handlers mh) {
    mio_handlers old;

    if (m == NULL || mh == NULL)
        return;

    old = m->mh;
    m->mh = mh;

    mio_handlers_free(old);
}
