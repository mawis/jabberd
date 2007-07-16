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
 * @file socket.cc
 * @brief some misc functions to handle sockets
 *
 * Hint: after creating a socket with these function, you probably want to register this socket in mio using mio_new().
 */

#include <jabberdlib.h>

/**
 * Simple wrapper to make socket creation easy.
 *
 * @param port port number of the socket
 * @param host hostname where to connect to or listen on
 * @param type type of socket (NETSOCKET_SERVER, NETSOCKET_CLIENT; or NETSOCKET_UDP)
 * @return file handle of the new socket
 */
int make_netsocket(u_short port, const char *host, int type) {
    int s, flag = 1;
#ifdef WITH_IPV6
    struct sockaddr_in6 sa;
    struct in6_addr *saddr;
#else
    struct sockaddr_in sa;
    struct in_addr *saddr;
#endif
    int socket_type;

    /* is this a UDP socket or a TCP socket? */
    socket_type = (type == NETSOCKET_UDP)?SOCK_DGRAM:SOCK_STREAM;

    bzero((void *)&sa,sizeof(sa));

#ifdef WITH_IPV6
    if((s = socket(PF_INET6,socket_type,0)) < 0)
#else
    if((s = socket(PF_INET,socket_type,0)) < 0)
#endif
        return(-1);
    if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&flag, sizeof(flag)) < 0)
        return(-1);

#ifdef WITH_IPV6
    saddr = make_addr_ipv6(host);
#else
    saddr = make_addr(host);
#endif
    if(saddr == NULL && type != NETSOCKET_UDP)
        return(-1);
#ifdef WITH_IPV6
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
#else
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
#endif

    if(type == NETSOCKET_SERVER)
    {
        /* bind to specific address if specified */
        if(host != NULL)
#ifdef WITH_IPV6
	    sa.sin6_addr = *saddr;
#else
            sa.sin_addr.s_addr = saddr->s_addr;
#endif

        if(bind(s,(struct sockaddr*)&sa,sizeof sa) < 0)
        {
            close(s);
            return(-1);
        }
    }
    if(type == NETSOCKET_CLIENT)
    {
#ifdef WITH_IPV6
	sa.sin6_addr = *saddr;
#else
        sa.sin_addr.s_addr = saddr->s_addr;
#endif
        if(connect(s,(struct sockaddr*)&sa,sizeof sa) < 0)
        {
            close(s);
            return(-1);
        }
    }
    if(type == NETSOCKET_UDP)
    {
        /* bind to all addresses for now */
        if(bind(s,(struct sockaddr*)&sa,sizeof sa) < 0)
        {
            close(s);
            return(-1);
        }

        /* if specified, use a default recipient for read/write */
        if(host != NULL && saddr != NULL)
        {
#ifdef WITH_IPV6
	    sa.sin6_addr = *saddr;
#else
            sa.sin_addr.s_addr = saddr->s_addr;
#endif
            if(connect(s,(struct sockaddr*)&sa,sizeof sa) < 0)
            {
                close(s);
                return(-1);
            }
        }
    }


    return(s);
}

/**
 * convert an IPv4 address or hostname to a in_addr structure
 *
 * @param host the IPv4 address or hostname to convert, on NULL, the hostname is used
 * @return the in_addr struct that holds the result (pointer to a static structure, overwritten on next call!)
 */
struct in_addr *make_addr(const char *host) {
    struct hostent *hp;
    static struct in_addr addr;
    char myname[MAXHOSTNAMELEN + 1];

    if (host == NULL || strlen(host) == 0) {
        gethostname(myname,MAXHOSTNAMELEN);
        hp = gethostbyname(myname);
        if(hp != NULL) {
            return (struct in_addr *) *hp->h_addr_list;
        }
    } else {
        addr.s_addr = inet_addr(host);
        if(addr.s_addr != -1) {
            return &addr;
        }
        hp = gethostbyname(host);
        if(hp != NULL) {
            return (struct in_addr *) *hp->h_addr_list;
        }
    }
    return NULL;
}

#ifdef WITH_IPV6
/**
 * map an in_addr struct to a in6_addr struct containing a mapped IPv4 address
 *
 * @param src the in_addr to map
 * @param dest where to place the mapped result address
 */
void _map_addr_to6(const struct in_addr *src, struct in6_addr *dest) {
    uint32_t hip;

    bzero(dest, sizeof(struct in6_addr));
    dest->s6_addr[10] = dest->s6_addr[11] = 0xff;

    hip = ntohl(src->s_addr);

    dest->s6_addr[15] = hip % 256;
    hip /= 256;
    dest->s6_addr[14] = hip % 256;
    hip /= 256;
    dest->s6_addr[13] = hip % 256;
    hip /= 256;
    dest->s6_addr[12] = hip % 256;
}

/**
 * convert an IPv4 or IPv6 address or hostname to a in6_addr structure
 *
 * @param host the IPv4 or IPv6 address or hostname to convert, on NULL, the hostname is used
 * @return the in6_addr struct that holds the result (pointer to a static structure, overwritten on next call!)
 */
struct in6_addr *make_addr_ipv6(const char *host) {
    static struct in6_addr addr;
    struct addrinfo hints;
    struct addrinfo *addr_res;
    int error_code;

    if (host == NULL || strlen(host) == 0) {
	char myname[MAXHOSTNAMELEN + 1];
        gethostname(myname,MAXHOSTNAMELEN);

	/* give the resolver hints on what we want */
	bzero(&hints, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	error_code = getaddrinfo(myname, NULL, &hints, &addr_res);
	if (error_code == 0) {
	    switch(addr_res->ai_family) {
		case PF_INET:
		    _map_addr_to6(&((struct sockaddr_in*)addr_res->ai_addr)->sin_addr, &addr);
		    break;
		case PF_INET6:
		    addr = ((struct sockaddr_in6*)addr_res->ai_addr)->sin6_addr;
		    break;
		default:
		    freeaddrinfo(addr_res);
		    return NULL;
	    }
	    freeaddrinfo(addr_res);
	    return &addr;
	}
    } else {
	char tempname[INET6_ADDRSTRLEN];

	/* IPv4 addresses have to be mapped to IPv6 */
	if (inet_pton(AF_INET, host, &addr)) {
	    strcpy(tempname, "::ffff:");
	    strcat(tempname, host);
	    host = tempname;
	}
	
	if (inet_pton(AF_INET6, host, &addr)) {
            return &addr;
        }
	
	/* give the resolver hints on what we want */
	bzero(&hints, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	error_code = getaddrinfo(host, NULL, &hints, &addr_res);
	if (error_code == 0) {
	    switch(addr_res->ai_family) {
		case PF_INET:
		    _map_addr_to6(&((struct sockaddr_in*)addr_res->ai_addr)->sin_addr, &addr);
		    break;
		case PF_INET6:
		    addr = ((struct sockaddr_in6*)addr_res->ai_addr)->sin6_addr;
		    break;
		default:
		    freeaddrinfo(addr_res);
		    return NULL;
	    }
	    freeaddrinfo(addr_res);
	    return &addr;
	}
    }
    return NULL;
}
#endif
