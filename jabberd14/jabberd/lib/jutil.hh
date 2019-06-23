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

#ifndef __JUTIL_HH
#define __JUTIL_HH

xmlnode
jutil_presnew(int type, char const *to,
              const char *status); /* Create a skeleton presence packet */
xmlnode jutil_iqnew(int type, char const *ns); /* Create a skeleton iq packet */
xmlnode jutil_msgnew(char const *type, char const *to, char const *subj,
                     char const *body);
/* Create a skeleton message packet */
int jutil_priority(xmlnode x); /* Determine priority of this packet */
void jutil_tofrom(xmlnode x);  /* Swaps to/from fields on a packet */
xmlnode
jutil_iqresult(xmlnode x); /* Generate a skeleton iq/result, given a iq/query */
char *jutil_timestamp(void); /* Get stringified timestamp */
char *jutil_timestamp_ms(
    char *buffer); /* Get stringified timestamp including milliseconds */
void jutil_error(xmlnode x, terror E); /* Append an <error> node to x */
void jutil_error_xmpp(
    xmlnode x, xterror E); /* Append an <error> node to x using XMPP syntax */
void jutil_error_map(terror old,
                     xterror *mapped); /* map an old terror structure to a new
                                          xterror structure */
void jutil_delay(xmlnode msg,
                 char const *reason); /* Append a delay packet to msg */
char *jutil_regkey(char *key,
                   char *seed); /* pass a seed to generate a key, pass the key
                                   again to validate (returns it) */

#endif // __JUTIL_HH
