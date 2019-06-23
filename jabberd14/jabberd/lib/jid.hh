/*
 * Copyrights
 *
 * Copyright (c) 2008-2019 Matthias Wimmer
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
#ifndef __JID_H
#define __JID_H

jid jid_new(pool p, const char *idstr); /* Creates a jabber id from the idstr */
void jid_set(jid id, const char *str,
             int item); /* Individually sets jid components */
char *jid_full(
    jid id); /* Builds a string type=user/resource@server from the jid data */
int jid_cmp(jid a, jid b); /* Compares two jid's, returns 0 for perfect match */
int jid_cmpx(jid a, jid b,
             int parts); /* Compares just the parts specified as JID_|JID_ */
jid jid_user(jid a); /* returns the same jid but just of the user@host part */
jid jid_user_pool(
    jid a, pool p); /* returns the same jid, but just the user@host part */
jid jid_append(jid a, jid b);

#endif // __JID_H
