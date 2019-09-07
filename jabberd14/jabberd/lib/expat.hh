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

#ifndef __EXPAT_HH
#define __EXPAT_HH

#include "xmlnode.hh"

void expat_startElement(void *userdata, const char *name, const char **atts);
void expat_endElement(void *userdata, const char *name);
void expat_charData(void *userdata, const char *s, int len);

xmlnode xmlnode_str(const char *str, int len);
xmlnode xmlnode_file(const char *file);
char const *xmlnode_file_borked(
    char const *file); /* same as _file but returns the parsing error */

int xmlnode2file(char const *file, xmlnode node); /* writes node to file */
int xmlnode2file_limited(char const *file, xmlnode node, size_t sizelimit);

void xmlnode_put_expat_attribs(xmlnode owner, const char **atts,
                               xmppd::ns_decl_list &nslist);

#endif // __EXPAT_HH
