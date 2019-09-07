/*
 * Copyrights
 *
 * Portions created by or assigned to Jabber.com, Inc. are
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2019 Matthias Wimmer
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

#ifndef __NAMESPACES_HH
#define __NAMESPACES_HH

#define NS_STREAM "http://etherx.jabber.org/streams"
#define NS_FLASHSTREAM "http://www.jabber.com/streams/flash"
#define NS_CLIENT "jabber:client"
#define NS_SERVER "jabber:server"
#define NS_DIALBACK "jabber:server:dialback"
#define NS_COMPONENT_ACCEPT "jabber:component:accept"
#define NS_AUTH "jabber:iq:auth"
#define NS_AUTH_CRYPT "jabber:iq:auth:crypt"
#define NS_REGISTER "jabber:iq:register"
#define NS_ROSTER "jabber:iq:roster"
#define NS_OFFLINE "jabber:x:offline"
#define NS_AGENT "jabber:iq:agent"
#define NS_AGENTS "jabber:iq:agents"
#define NS_DELAY "jabber:x:delay"
#define NS_VERSION "jabber:iq:version"
#define NS_TIME "jabber:iq:time"
#define NS_VCARD "vcard-temp"
#define NS_PRIVATE "jabber:iq:private"
#define NS_SEARCH "jabber:iq:search"
#define NS_OOB "jabber:iq:oob"
#define NS_XOOB "jabber:x:oob"
#define NS_FILTER "jabber:iq:filter"
#define NS_AUTH_0K "jabber:iq:auth:0k"
#define NS_BROWSE "jabber:iq:browse"
#define NS_EVENT "jabber:x:event"
#define NS_CONFERENCE "jabber:iq:conference"
#define NS_SIGNED "jabber:x:signed"
#define NS_ENCRYPTED "jabber:x:encrypted"
#define NS_GATEWAY "jabber:iq:gateway"
#define NS_LAST "jabber:iq:last"
#define NS_ENVELOPE "jabber:x:envelope"
#define NS_EXPIRE "jabber:x:expire"
#define NS_PRIVACY "jabber:iq:privacy"
#define NS_XHTML "http://www.w3.org/1999/xhtml"
#define NS_DISCO_INFO "http://jabber.org/protocol/disco#info"
#define NS_DISCO_ITEMS "http://jabber.org/protocol/disco#items"
#define NS_DATA "jabber:x:data"
#define NS_FLEXIBLE_OFFLINE "http://jabber.org/protocol/offline"
#define NS_IQ_AUTH "http://jabber.org/features/iq-auth"
#define NS_REGISTER_FEATURE "http://jabber.org/features/iq-register"
#define NS_MSGOFFLINE "msgoffline"
#define NS_BYTESTREAMS "http://jabber.org/protocol/bytestreams"
#define NS_COMMAND "http://jabber.org/protocol/commands"

/* #define NS_XDBGINSERT "jabber:xdb:ginsert" XXX: I guess this it not used
 * ANYWHERE and can be deleted */
#define NS_XDBNSLIST "jabber:xdb:nslist"

#define NS_XMPP_STANZAS "urn:ietf:params:xml:ns:xmpp-stanzas"
#define NS_XMPP_TLS "urn:ietf:params:xml:ns:xmpp-tls"
#define NS_XMPP_STREAMS "urn:ietf:params:xml:ns:xmpp-streams"
#define NS_XMPP_SASL "urn:ietf:params:xml:ns:xmpp-sasl"

#define NS_XMPP_PING "urn:xmpp:ping"

#define NS_JABBERD_STOREDPRESENCE "http://jabberd.org/ns/storedpresence"
#define NS_JABBERD_STOREDPEERPRESENCE "http://jabberd.org/ns/storedpeerpresence"
#define NS_JABBERD_STOREDREQUEST                                               \
    "http://jabberd.org/ns/storedsubscriptionrequest"
#define NS_JABBERD_STOREDSTATE                                                 \
    "http://jabberd.org/ns/storedstate" /**< namespace to store internal state \
                                           of jabberd */
#define NS_JABBERD_HISTORY "http://jabberd.org/ns/history"
#define NS_JABBERD_HASH                                                        \
    "http://jabberd.org/ns/hash" /**< namespace for storing xhash data */
#define NS_JABBERD_XDB                                                         \
    "http://jabberd.org/ns/xdb" /**< namespace for the root element used by    \
                                   xdb_file to store data in files */
#define NS_JABBERD_WRAPPER                                                     \
    "http://jabberd.org/ns/wrapper" /**< namespace used to wrap various        \
                                       internal data */
#define NS_JABBERD_XDBSQL                                                      \
    "http://jabberd.org/ns/xdbsql" /**< namespace for substitution in xdb_sql  \
                                      configuration */
#define NS_JABBERD_ACL                                                         \
    "http://jabberd.org/ns/acl" /**< namespace for access control lists */
#define NS_JABBERD_LOOPCHECK                                                   \
    "http://jabberd.org/ns/loopcheck" /**< namespace for loopchecking of s2s   \
                                         connections */
#define NS_JABBERD_ERRMSG                                                      \
    "http://jabberd.org/ns/errmsg" /**< namespace for session control error    \
                                      messages */

#define NS_SESSION                                                                                               \
    "http://jabberd.jabberstudio.org/ns/session/1.0" /**< namespace of the                                       \
                                                        jabberd2 session                                         \
                                                        control protocol                                         \
                                                        (http://jabberd.jabberstudio.org/dev/docs/session.shtml) \
                                                      */

#define NS_XMLNS                                                               \
    "http://www.w3.org/2000/xmlns/" /**< namespace of xml namespace            \
                                       declarations, defined by 'Namespaces in \
                                       XML' (W3C) */
#define NS_XML                                                                 \
    "http://www.w3.org/XML/1998/namespace" /**< namespace declared by the xml  \
                                              prefix, defined by 'Namespaces   \
                                              in XML' (W3C) */

#define NS_JABBERD_CONFIGFILE                                                  \
    "http://jabberd.org/ns/configfile" /**< namespace of the root element in   \
                                          the config file */
#define NS_JABBERD_CONFIGFILE_REPLACE                                          \
    "http://jabberd.org/ns/configfile/replace" /**< namespace of replace and   \
                                                  include commands */
#define NS_JABBERD_CONFIGFILE_ROUTER                                           \
    "http://xmppd.org/ns/configfile/router" /**< namespace for global router   \
                                               configuration */
#define NS_JABBERD_CONFIG_XDBFILE                                              \
    "jabber:config:xdb_file" /**< namespace of xdb_file component              \
                                configuration */
#define NS_JABBERD_CONFIG_DIALBACK                                             \
    "jabber:config:dialback" /**< namespace of dialback component              \
                                configuration */
#define NS_JABBERD_CONFIG_DNSRV                                                \
    "jabber:config:dnsrv" /**< namespace of the dnsrv component configuration  \
                           */
#define NS_JABBERD_CONFIG_JSM                                                  \
    "jabber:config:jsm" /**< namespace of the jsm component configuration */
#define NS_JABBERD_CONFIG_PTHCSOCK                                             \
    "jabber:config:pth-csock" /**< namespace of the pthsock_client component   \
                                 configuration */
#define NS_JABBERD_CONFIG_XDBSQL                                               \
    "jabber:config:xdb_sql" /**< namepace of the xdb_sql component             \
                               configuration */
#define NS_JABBERD_CONFIG_DYNAMICHOST                                          \
    "http://xmppd.org/ns/dynamichost" /**< namespace of the dynamic            \
                                         configuration of additional hosts for \
                                         components */

#endif // __NAMESPACES_HH
