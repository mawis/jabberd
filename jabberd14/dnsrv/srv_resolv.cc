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

#include "jabberd.h"

#include <netinet/in.h>
#define BIND_8_COMPAT
#include <arpa/nameser.h>
#include <resolv.h>

#include "srv_resolv.h"

/**
 * @file srv_resolv.cc
 * @brief implements SRV DNS resolving
 *
 * This file implements resolving of services in the DNS using the protocol defined in RFC 2782.
 */

#ifndef T_SRV
#define T_SRV 33
#endif

/**
 * @brief representation of a SRV DNS record
 *
 * This structure is used to build an ordered double linked list of SRV DNS records for a service on a domain
 */
typedef struct __srv_list
{
     int   priority;	/**< priority value in this record */
     char* port;	/**< port value in this record */
     char* host;	/**< host name where this record points to */
     struct __srv_list* next; /**< next value in the list (higher priority value) */
     struct __srv_list* last; /**< previous value in the list (lower priority value) */
} *srv_list, _srv_list;

/**
 * convert an IPv4 (AF_INET) address to its textual representation using memory pools
 *
 * @param p the pool to be used
 * @param addrptr the address that should be printed
 * @return the address as a string
 */
char* srv_inet_ntoa(pool p, unsigned char* addrptr)
{
     char result[16];
     result[15] = '\0';
     snprintf(result, sizeof(result), "%d.%d.%d.%d", addrptr[0], addrptr[1], addrptr[2], addrptr[3]);
     return pstrdup(p, result);
}

#ifdef WITH_IPV6
/**
 * convert an internet address to its textual representation using memory pools
 *
 * @param p the pool to be used
 * @param addrptr the address that should be printed
 * @param af the address family of addrptr
 * @return the address as a string
 */
char* srv_inet_ntop(pool p, const unsigned char* addrptr, int af)
{
    char result[INET6_ADDRSTRLEN];
    inet_ntop(af, addrptr, result, sizeof(result));
    return pstrdup(p, result);
}
#endif

/**
 * convert a (numerical) port number to a string using memory pools
 *
 * @param p the pool to be used
 * @param port the port that should be converted
 * @return the port number as a string
 */
char* srv_port2str(pool p, unsigned short port)
{
     char* result = static_cast<char*>(pmalloco(p, 6));
     snprintf(result, 6, "%d", port);
     return result;
}

/**
 * put a value in an xhash and join it with the previous value if there has been already one in the hash
 *
 * If there is no entry for this key, the function just enters the value.
 * If there is already an entry for this key, the function will append a ","
 * and the old value to the new value and insert it into the hash.
 *
 * @param p memory pool to be used
 * @param ht the hash table
 * @param key the key in the hash
 * @param value the value that should be inserted
 */
void srv_xhash_join(pool p, xht ht, const char *key, char *value) {
    void *old = xhash_get(ht, key);
    if (old == NULL) {
	xhash_put(ht, key, value);
	return;
    }
    xhash_put(ht, key, spools(p, value, ",", (char*)old, p));
}

/**
 * helper function that lookups AAAA and A records in the dns
 *
 * this function will lookup AAAA and A records and return the IP addresses as a comma separated list
 *
 * @return 0 in case of success, non zero on error
 */
int srv_lookup_aaaa_a(spool result, const char* domain) {
    int			first_result = 1;
#ifdef WITH_IPV6
    int			error_code;
    struct addrinfo	hints;
    struct addrinfo*	addr_res;
    struct addrinfo*	addr_iter;
    char		addr_str[INET6_ADDRSTRLEN];
#else
    struct hostent*	hp;
    char		addr_str[16];
#endif
    
    log_debug2(ZONE, LOGT_IO, "Standard resolution of %s", domain);
    
#ifdef WITH_IPV6
    /* setup the hints what we want to get */
    bzero(&hints, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addr_res = NULL;
  
    /* start resolving */
    error_code = getaddrinfo(domain, NULL, &hints, &addr_res);
    if (error_code) {
	log_debug2(ZONE, LOGT_IO, "Error while resolving %s: %s", domain, gai_strerror(error_code));
	if (addr_res) {
	    freeaddrinfo(addr_res);
	}
	return 1;
    }

    /* iterate through all results to find IPv6 and IPv4 results */
    for (addr_iter = addr_res; addr_iter != NULL; addr_iter = addr_iter->ai_next) {
	switch (addr_iter->ai_family) {
	    case PF_INET:
		inet_ntop(AF_INET, (char *)&((struct sockaddr_in*)addr_iter->ai_addr)->sin_addr, addr_str, sizeof(addr_str));
		if (!first_result) {
		    spooler(result, ",", addr_str, result);
		} else {
		    first_result = 0;
		    spool_add(result, addr_str);
		}
		break;
	    case PF_INET6:
		inet_ntop(AF_INET6, (char *)&((struct sockaddr_in6*)addr_iter->ai_addr)->sin6_addr, addr_str, sizeof(addr_str));
		if (!first_result) {
		    spooler(result, ",", addr_str, result);
		} else {
		    first_result = 0;
		    spool_add(result, addr_str);
		}
	}
    }

    /* free memory */
    if (addr_res) {
	freeaddrinfo(addr_res);
    }

    return 0;
#else
    hp = gethostbyname(domain);
    if (!hp) {
	log_debug2(ZONE, LOGT_IO, "Unable to resolve: %s", domain);
	return 1;
    }
    
    snprintf(addr_str, sizeof(addr_str), "%u.%u.%u.%u", (unsigned char)(hp->h_addr[0]), (unsigned char)hp->h_addr[1], (unsigned char)hp->h_addr[2], (unsigned char)hp->h_addr[3]);
    spooler(result, addr_str, result);
    return 0;
#endif
}

/**
 * do a DNS lookup
 *
 * This function implements a SRV DNS lookup and falls back to normal AAAA/A resolution
 * if no service has been given by the caller.
 *
 * @param p memory pool to be used by this function
 * @param service which service should be looked up (e.g. "_xmpp-server._tcp")
 * @param domain which domain should be looked up
 * @return comma separated list of results containing IPv4 and IPv6 addresses with or without ports
 *
 * @todo The function honors the priority values of a SRV record but not the weight values. Implement handling of weights!
 */
char* srv_lookup(pool p, const char* service, const char* domain)
{
     unsigned char    reply[1024];	   /* Reply buffer */
     int              replylen = 0;
     char             host[1024];
     register HEADER* rheader;		   /* Reply header*/
     unsigned char*   rrptr;		   /* Current Resource record ptr */
     int              exprc;		   /* dn_expand return code */
     int              rrtype;
     long             rrpayloadsz;
     srv_list       svrlist  = NULL;
     srv_list       tempnode = NULL;
     srv_list       iternode = NULL;
     xht	      arr_table;	   /* Hash of A records (name, ip) */
     spool            result;
     int	      result_is_empty = 1;
     char*            ipname;
     char*            ipaddr;
#ifdef WITH_IPV6
     int	      error_code;
     struct addrinfo  hints;
     struct addrinfo* addr_res;
#else
     struct hostent*  hp;
#endif

    /* If no service is specified, use a standard gethostbyname call */
    if (service == NULL) {
	result = spool_new(p);
	if (srv_lookup_aaaa_a(result, domain) == 0) {
	    return spool_print(result);
	} else {
	    return NULL;
	}
    }

    log_debug2(ZONE, LOGT_IO, "srv: SRV resolution of %s.%s", service, domain);

    /* Setup A record hash table */
    arr_table = xhash_new(11);

    /* Initialize lookup system if needed (check global _res structure) */
    if (((_res.options & RES_INIT) == 0) && (res_init() == -1)) {
	log_debug2(ZONE, LOGT_IO, "srv: initialization failed on res_init.");
	return NULL;
    }

    /* Run a SRV query against the specified domain */
    replylen = res_querydomain(service, domain,
	    C_IN,			/* Class */
	    T_SRV,			/* Type */
	    (unsigned char*)&reply,	/* Answer buffer */
	    sizeof(reply));		/* Answer buffer sz */

    /* Setup a pointer to the reply header */
    rheader = (HEADER*)reply;

    /* Process SRV response if all conditions are met per RFC 2052:
     * 1.) reply has some data available
     * 2.) no error occurred
     * 3.) there are 1 or more answers available */
    if ( (replylen > 0) && (ntohs(rheader->rcode) == NOERROR) && (ntohs(rheader->ancount) > 0) ) {
	/* Parse out the Question section, and get to the following 
	 * RRs (see RFC 1035-4.1.2) */
	exprc = dn_expand(reply,	/* Msg ptr */
		reply + replylen,	/* End of msg ptr */
		reply + sizeof(HEADER),	/* Offset into msg */
		host, sizeof(host));	/* Dest buffer for expansion */
	if (exprc < 0) {
	    log_debug2(ZONE, LOGT_IO, "srv: DN expansion failed for Question section.");
	    return NULL;
	}

	/* Determine offset of the first RR */
	rrptr = reply + sizeof(HEADER) + exprc + 4;

	/* Walk the RRs, building a list of targets */
	while (rrptr < (reply + replylen)) {
	    /* Expand the domain name */
	    exprc = dn_expand(reply, reply + replylen, rrptr, host, sizeof(host));
	    if (exprc < 0) {
		log_debug2(ZONE, LOGT_IO, "srv: Whoa nelly! DN expansion failed for RR.");
		return NULL;
	    }

	    /* Jump to RR info */
	    rrptr += exprc;
	    rrtype      = (rrptr[0] << 8 | rrptr[1]);  /* Extract RR type */
	    rrpayloadsz = (rrptr[8] << 8 | rrptr[9]);  /* Extract RR payload size */
	    rrptr += 10;

	    /* Process the RR */
	    switch(rrtype) {
#ifdef WITH_IPV6
		/* AAAA records should be hashed for the duration of this lookup */
		case T_AAAA:
		    /* Allocate a new string to hold the IP address */
		    ipaddr = srv_inet_ntop(p, rrptr, AF_INET6);
		    /* Copy the domain name */
		    ipname = pstrdup(p, host);

		    /* Insert name/ip into hash table for future reference */
		    srv_xhash_join(p, arr_table, ipname, ipaddr);

		   break;
#endif
		/* A records should be hashed for the duration of this lookup */
		case T_A: 
		    /* Allocate a new string to hold the IP address */
		    ipaddr = srv_inet_ntoa(p, rrptr);
		    /* Copy the domain name */
		    ipname = pstrdup(p, host);

		    /* Insert name/ip into hash table for future reference */
		    srv_xhash_join(p, arr_table, ipname, ipaddr);
		    
		    break;

		/* SRV records should be stored in a sorted list */
		case T_SRV:
		    /* Expand the target name */
		    exprc = dn_expand(reply, reply + replylen, rrptr + 6, host, sizeof(host));
		    if (exprc < 0) {
			log_debug2(ZONE, LOGT_IO, "srv: DN expansion failed for SRV.");
			return NULL;
		    }

		    /* Create a new node */
		    tempnode = static_cast<srv_list>(pmalloco(p, sizeof(_srv_list)));
		    tempnode->priority = (rrptr[0] << 8 | rrptr[1]);
		    tempnode->port     = srv_port2str(p, (rrptr[4] << 8 | rrptr[5]));
		    tempnode->host     = pstrdup(p, host);

		    log_debug2(ZONE, LOGT_IO, "found SRV record pointing to %s", tempnode->host);

		    /* Insert the node in the list */		    
		    if (svrlist == NULL) {
			/* first result */
			svrlist = tempnode;
		    } else {
			srv_list iternode_before = NULL;

			/* insert result in ordered list */
			iternode = svrlist;	/* HEAD of list (smallest priority value) */
			
			/* find element that stays in front of the new one */
			/* XXX for elements with the same priority we should use the weight to order
			 * the elements in the list. We are now just ignoring the weight resulting
			 * in an equal distribution across results of the same priority */
			while (iternode != NULL && iternode->priority < tempnode->priority) {
			    iternode_before = iternode; /* keep pointer to the element before */
			    iternode = iternode->next;	/* switch to next element */
			}

			/* iternode now either points to NULL (insert as last element)
			 * or it points to the element after the new one
			 *
			 * iternode_before now either point to NULL (insert as first element)
			 * or it points to the element in front of the new one */

			/* insert the new element in the list */

			/* update pointers in the new element */
			tempnode->next = iternode;
			tempnode->last = iternode_before;

			/* update pointer in the previous element */
			if (iternode_before != NULL) {
			    iternode_before->next = tempnode;
			} else {
			    /* we are the first element */
			    svrlist = tempnode;
			}

			/* update pointer in the following element */
			if (iternode != NULL) {
			    iternode->last = tempnode;
			}
		    }
	    } /* end..switch */

	    /* Increment to next RR */
	    rrptr += rrpayloadsz;
	}

	/* Now, walk the nicely sorted list and resolve the target's A records, sticking the resolved name in
	 * a spooler -- hopefully these have been pre-cached, and arrived along with the SRV reply */
	result = spool_new(p);

	iternode = svrlist;
	while (iternode != NULL) {
	    log_debug2(ZONE, LOGT_IO, "processing SRV record pointing to %s", iternode->host);

	    /* Check the AAAA/A record hash table first.. */
	    ipaddr = (char*)xhash_get(arr_table, iternode->host);

	    /* it hasn't been in the additional section, we have to lookup the IP address */
	    if (ipaddr == NULL) {
		spool temp_result = spool_new(p);

		log_debug2(ZONE, LOGT_IO, "'%s' not in additional section of DNS reply, looking it up using AAAA/A query", iternode->host);
		srv_lookup_aaaa_a(temp_result, iternode->host);
		ipaddr = spool_print(temp_result);
	    }
	   
	    if (j_strlen(ipaddr) > 0) {
		/* copy the ipaddr as we will modify it */
		char *ptrptr, *token, *ipaddr_copy = strdup(ipaddr);

		/* if there has been a result already, we have to separate by a "," */
		if (!result_is_empty) {
		    spool_add(result, ",");
		} else {
		    result_is_empty = 0;
		}

		/* add the port number for each address */
		token = strtok_r(ipaddr_copy, ",", &ptrptr);
		while (token != NULL) {
		    if (strchr(token, ':')) {
			/* IPv6 format */
			spooler(result, "[", token, "]:", iternode->port, result);
		    } else {
			/* IPv4 format */
			spooler(result, token, ":", iternode->port, result);
		    }
		    /* get next token */
		    token = strtok_r(NULL, ",", &ptrptr);
		    if (token) {
			spool_add(result, ","); /* separate results by ',' */
		    }
		}
		/* free our tokenized copy */
		free(ipaddr_copy);
	    }
	    iternode = iternode->next;
	}
	/* Finally, turn the fully resolved list into a string <ip>:<host>,... */
	return spool_print(result);
    }
    /* Otherwise, return NULL -- it's for the caller to finish up by using
     * standard A records */
    return NULL;	
}
