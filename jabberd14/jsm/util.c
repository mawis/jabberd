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
 *  Copyright (C) 1998-2000 The Jabber Team http://jabber.org/
 *
 *  util.c -- utility functions for jsm
 *
 */

#include "jsm.h"

/*
 *  js_bounce -- short_desc
 *  
 *  Long_description
 *
 *  parameters
 *  	x -- the node to bounce
 *      terr - the error code describing the reason for the bounce
 *
 */
void js_bounce(xmlnode x, terror terr)
{
    /* if the node is a subscription */
    if(j_strcmp(xmlnode_get_name(x),"presence") == 0 && j_strcmp(xmlnode_get_attrib(x,"type"),"subscribe") == 0)
    {
        /* turn the node into a result tag. it's a hack, but it get's the job done */
        jutil_iqresult(x);
        xmlnode_put_attrib(x,"type","unsubscribed");
        xmlnode_insert_cdata(xmlnode_insert_tag(x,"status"),terr.msg,-1);

        /* deliver it back to the client */
        js_deliver(jpacket_new(x));
        return;

    }

    /* if it's a presence packet, just drop it */
    if(j_strcmp(xmlnode_get_name(x),"presence") == 0 || j_strcmp(xmlnode_get_attrib(x,"type"),"error") == 0)
    {
        log_debug(ZONE,"dropping %d packet %s",terr.code,xmlnode2str(x));
        xmlnode_free(x);
        return;
    }

    /* if it's neither of these, make an error message an deliver it */
    jutil_error(x, terr);
    js_deliver(jpacket_new(x));

}


/*
 *  js_config -- get a configuration node
 *
 *  parameters
 *      si -- session instance
 *      query -- the path through the tag hierarchy of the desired tag
 *               eg. for the conf file <foo><bar>bar value</bar><baz/><foo>
 *               use "foo/bar" to retreive the bar node
 *
 *  returns
 *      a pointer to the xmlnode specified in query
 *      or the root config node if query is null
 */
xmlnode js_config(jsmi si, char *query)
{

    log_debug(ZONE,"config query %s",query);

    if(query == NULL)
        return si->config;
    else
        return xmlnode_get_tag(si->config, query);
}

