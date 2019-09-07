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
 * @dir lib
 * @brief Contains basic functionality, that is needed to form the server and
 * its components
 *
 * In this directory there is the basic functionality on which the jabber server
 * is build.
 *
 * Maybe the most basic file in here is pool.cc which contains the memory
 * management of jabberd14. Memory in jabberd14 is managed in this pools, which
 * means, that all memory allocated on a pool gets freed together when this pool
 * is freed. This allows, that we do not need that many single memory freeings,
 * and therefore the risk that freeing memory is forgotten gets reduced.
 *
 * Another basic module is in jid.cc which contains the functionality to manage
 * XMPP addresses (JIDs). It can be used to modify and compare JIDs as well as
 * to get them normalized.
 *
 * The third most basic module is in xmlnode.cc which contains a DOM-like
 * interface to XML trees. Based on this XML interface jabberd14 builds the
 * jpacket_struct which combines an XML document (a stanza) with fields of
 * relevant information about this stanza (stanza type, sender and receipient,
 * ...) jpackets are implemented in jpacket.cc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pth.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <expat.h>

#include <list>
#include <utility>

#include <unordered_map>

#include <glibmm.h>


#ifndef INCL_LIB_H
#define INCL_LIB_H

#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "hash.hh"
#include "pool.hh"
#include "socket.hh"
#include "str.hh"
#include "base64.hh"
#include "crc32.hh"
#include "xhash.hh"
#include "xmlnode.hh"
#include "expat.hh"
#include "xstream.hh"
#include "hmac.hh"
#include "jabberid.hh"
#include "jid.hh"
#include "jpacket.hh"
#include "rate.hh"
#include "karma.hh"
#include "namespaces.hh"
#include "jutil.hh"
#include "messages.hh"
#include "lwresc.hh"

#endif /* INCL_LIB_H */
