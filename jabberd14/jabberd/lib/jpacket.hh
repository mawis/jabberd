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

#ifndef __JPACKET_HH
#define __JPACKET_HH

#define JPACKET_UNKNOWN 0x00
#define JPACKET_MESSAGE 0x01
#define JPACKET_PRESENCE 0x02
#define JPACKET_IQ 0x04
#define JPACKET_S10N 0x08

#define JPACKET__UNKNOWN 0
#define JPACKET__NONE 1
#define JPACKET__ERROR 2
#define JPACKET__CHAT 3
#define JPACKET__GROUPCHAT 4
#define JPACKET__GET 5
#define JPACKET__SET 6
#define JPACKET__RESULT 7
#define JPACKET__SUBSCRIBE 8
#define JPACKET__SUBSCRIBED 9
#define JPACKET__UNSUBSCRIBE 10
#define JPACKET__UNSUBSCRIBED 11
#define JPACKET__AVAILABLE 12
#define JPACKET__UNAVAILABLE 13
#define JPACKET__PROBE 14
#define JPACKET__HEADLINE 15
#define JPACKET__INVISIBLE 16

typedef struct jpacket_struct {
    unsigned char type; /**< stanza type (JPACKET_*) */
    int subtype;        /**< subtype of a stanza */
    int flag;   /**< used by the session manager to flag messages, that are read
                   from offline storage */
    void *aux1; /**< pointer to data passed around with a jpacket, multiple use
                   inside jsm */
    xmlnode x;  /**< xmlnode containing the stanza inside the jpacket */
    jid to;     /**< destination of the stanza */
    jid from;   /**< source address for the stanza */
    char *iqns; /**< pointer to the namespace inside an IQ stanza */
    xmlnode iq; /**< "content" of an iq stanza, pointer to the element in its
                   own namespace */
    pool p;     /**< memory pool used for this stanza */
} * jpacket, _jpacket;

jpacket jpacket_new(xmlnode x); /* Creates a jabber packet from the xmlnode */
jpacket
jpacket_reset(jpacket p); /* Resets the jpacket values based on the xmlnode */
int jpacket_subtype(
    jpacket p); /* Returns the subtype value (looks at xmlnode for it) */

#endif // __JPACKET_HH
