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

#include <jsm.h>

mreturn mod_auth_digest_yum(mapi m, void *arg)
{
    spool s;
    char *sid;
    char *digest;
    char *passxdb;
    char *mydigest;
    xmlnode xdb;

    log_debug("mod_auth_digest","checking");

    if(jpacket_subtype(m->packet) == JPACKET__GET)
    { /* type=get means we flag that the server can do digest auth */
        xmlnode_insert_tag(m->packet->iq,"digest");
        return M_PASS;
    }

    if((digest = xmlnode_get_tag_data(m->packet->iq,"digest")) == NULL)
        return M_PASS;

    xdb = xdb_get(m->si->xc, m->user->id->server, m->user->id, NS_AUTH);
    passxdb = xmlnode_get_data(xdb);
    sid = xmlnode_get_attrib(xmlnode_get_tag(m->packet->iq,"digest"), "sid");

    /* Concat the stream id and password */
    /* SHA it up */
    log_debug("mod_auth_digest", "Got SID: %s", sid);
    s = spool_new(m->packet->p);
    spooler(s,sid,passxdb,s);

    mydigest = shahash(spool_print(s));

    /* don't need the xdb data anymore */
    xmlnode_free(xdb);

    log_debug("mod_auth_digest","comparing %s %s",digest,mydigest);

    if(digest == NULL || sid == NULL || mydigest == NULL) return M_PASS;

    if(strcmp(digest, mydigest) != 0)
        jutil_error(m->packet->x, TERROR_AUTH);
    else
        jutil_iqresult(m->packet->x);

    return M_HANDLED;
}

void mod_auth_digest(jsmi si)
{
    log_debug("mod_auth_digest","init");
    js_mapi_register(si,e_AUTH, mod_auth_digest_yum, NULL);
}
