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
 * 
 * --------------------------------------------------------------------------*/

#include "lib.h"

/* socket.c
 *
 * Simple wrapper to make socket creation easy.
 * type = NETSOCKET_SERVER is local listening socket
 * type = NETSOCKET_CLIENT is connection socket
 * type = NETSOCKET_UDP is a UDP connection socket
 */

int make_netsocket(u_short port, char *host, int type)
{
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


struct in_addr *make_addr(char *host)
{
    struct hostent *hp;
    static struct in_addr addr;
    char myname[MAXHOSTNAMELEN + 1];

    if(host == NULL || strlen(host) == 0)
    {
        gethostname(myname,MAXHOSTNAMELEN);
        hp = gethostbyname(myname);
        if(hp != NULL)
        {
            return (struct in_addr *) *hp->h_addr_list;
        }
    }else{
        addr.s_addr = inet_addr(host);
        if(addr.s_addr != -1)
        {
            return &addr;
        }
        hp = gethostbyname(host);
        if(hp != NULL)
        {
            return (struct in_addr *) *hp->h_addr_list;
        }
    }
    return NULL;
}

#ifdef WITH_IPV6
struct in6_addr *make_addr_ipv6(char *host)
{
    struct hostent *hp;
    static struct in6_addr addr;

    if(host == NULL || strlen(host) == 0)
    {
	char myname[MAXHOSTNAMELEN + 1];
        gethostname(myname,MAXHOSTNAMELEN);

	/* configure resolver to use IPv6 for gethostbyname */
	/* this isn't thread save, but gethostbyname neither */
	if (!(_res.options&RES_INIT))
	    res_init();
	_res.options |= RES_USE_INET6;

        hp = gethostbyname(myname);

	/* disable IPv6 for gethostbyname again */
	_res.options &= ~RES_USE_INET6;
	
        if(hp != NULL)
        {
            return (struct in6_addr *) *hp->h_addr_list;
        }
    }else{
	char tempname[INET6_ADDRSTRLEN];

	/* IPv4 addresses have to be mapped to IPv6 */
	if (inet_pton(AF_INET, host, &addr))
	{
	    strcpy(tempname, "::ffff:");
	    strcat(tempname, host);
	    host = tempname;
	}
	
	if (inet_pton(AF_INET6, host, &addr))
        {
            return &addr;
        }

	/* configure resolver to use IPv6 for gethostbyname */
	/* this isn't thread save, but gethostbyname neither */
	if (!(_res.options&RES_INIT))
	    res_init();
	_res.options |= RES_USE_INET6;

        hp = gethostbyname(host);

	/* disable IPv6 for gethostbyname again */
	_res.options &= ~RES_USE_INET6;
	
        if(hp != NULL)
        {
            return (struct in6_addr *) *hp->h_addr_list;
        }
    }
    return NULL;
}
#endif

/* Sets a file descriptor to close on exec.  "flag" is 1 to close on exec, 0 to
 * leave open across exec.
 * -- EJB 7/31/2000
 */
int set_fd_close_on_exec(int fd, int flag)
{
    int oldflags = fcntl(fd,F_GETFL);
    int newflags;

    if(flag)
        newflags = oldflags | FD_CLOEXEC;
    else
        newflags = oldflags & (~FD_CLOEXEC);

    if(newflags==oldflags)
        return 0;
    return fcntl(fd,F_SETFL,(long)newflags);
}

