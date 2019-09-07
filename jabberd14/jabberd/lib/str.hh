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
#ifndef __STR_HH
#define __STR_HH

#define ZONE zonestr(__FILE__, __LINE__)
char *zonestr(char const *file, int line);

char *j_strdup(char const *str);
char *j_strcat(char *dest, char const *txt);
int j_strcmp(char const *a, char const *b);
int j_strcasecmp(char const *a, char const *b);
int j_strncmp(char const *a, char const *b, int i);
int j_strncasecmp(char const *a, char const *b, int i);
int j_strlen(char const *a);
int j_atoi(char const *a, int def);

namespace xmppd {
class to_lower {
public:
  to_lower(std::locale const &l) : loc(l) {}
  char operator()(char c) const { return std::tolower(c, loc); }

private:
  std::locale const &loc;
};
} // namespace xmppd

char *strescape(pool p, char *buf); /* Escape <>&'" chars */
char *strunescape(pool p, char *buf);
std::string strescape(std::string s);

#endif // __STR_HH
