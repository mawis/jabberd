/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  Jabber
 *  Copyright (C) 1998-1999 The Jabber Team http://jabber.org/
 */

#include "jabberd.h"

/* 

to compile:

   gcc -fPIC -shared -o test.so test.c -I../src

jabberd.xml:

  <service id="test section">
    <host>test</host>
    <load><test>../load/test.so</test></load>
    <testing xmlns="test"><a>foo</a>bar</testing>
  </service>

*/

void test(instance i, xmlnode x)
{
    xmlnode config;
    xdbcache xc;

    log_debug(ZONE,"lala, test loading!");

    xc = xdb_cache(i);
    config = xdb_get(xc, NULL, jid_new(xmlnode_pool(x),"config@-internal"),"test");

    log_debug(ZONE,"test loaded, got config %s",xmlnode2str(config));

}
