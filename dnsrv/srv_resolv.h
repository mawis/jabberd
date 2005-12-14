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

#ifdef __cplusplus
extern "C" {
#endif

char* srv_lookup(pool p, const char* service, const char* domain);

#ifdef __cplusplus
}
#endif

#endif
