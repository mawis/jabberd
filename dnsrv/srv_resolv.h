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
 * @dir dnsrv
 * @brief implement the DNS resolver of jabberd14
 *
 * The dnsrv component implements the DNS resolver. It might be important to note, that this
 * resolver is doing all resolving by just using DNS queries. It does not read the /etc/hosts
 * file on unix systems. Therefore jabberd in general ignores the contents of this file.
 *
 * The dnsrv component is normally registered for the default routing in the
 * @link jabberd jabberd XML router@endlink and therefore gets all stanzas not intended
 * to be delivered locally. The dnsrv component than starts resolving of the domain, tags
 * the stanza with the IP addresses of the foreign host and then resends the tagged stanza
 * to one of the @link dialback server connection managers,@endlink that are configured in
 * the configuration section of the dnsrv component. This resending is done by wrapping
 * the stanza in a &lt;route/&gt; stanza.
 */
#ifndef INCL_SRV_RESOLV_H
#define INCL_SRV_RESOLV_H

char* srv_lookup(pool p, const char* service, const char* domain);

#endif
