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

/* actually filter the packet */
result base_ns_filter(instance i, dpacket p, void *arg)
{
    xmlnode x = (xmlnode)arg;

    /* check all the <ns>...</ns> elements, success if any one of them matches */
    for(x = xmlnode_get_firstchild(x); x != NULL; x = xmlnode_get_nextsibling(x))
        if(j_strcmp(p->id->resource, xmlnode_get_data(x)) == 0)
            return r_PASS;

    return r_ERR;
}

result base_ns_config(instance id, xmlnode x, void *arg)
{
    xmlnode ns;

    if(id == NULL)
    {
        log_debug(ZONE,"base_ns_config validating configuration\n");
        if(xmlnode_get_data(x) == NULL)
            return r_ERR;
        return r_PASS;
    }

    log_debug(ZONE,"base_ns_config performing configuration %s\n",xmlnode2str(x));

    /* XXX uhgly, should figure out how to flag errors like this more consistently, during checking phase or something */
    if(id->type != p_XDB)
    {
        log_debug(ZONE,"<ns>...</ns> element only allowed in xdb section\n");
        return r_ERR;
    }

    /* hack hack away, ugly but effective... we need to correlate all the <ns> elements within an instance, hide them together in an xmlnode in an attrib on the id */
    ns = (xmlnode)xmlnode_get_vattrib(id->x, "base_ns");
    if(ns == NULL)
    {
        ns = xmlnode_new_tag_pool(xmlnode_pool(id->x),"ns");
        xmlnode_put_vattrib(id->x,"base_ns",(void *)ns);
    }
    xmlnode_insert_tag_node(ns,x);

    register_phandler(id, o_COND, base_ns_filter, (void *)ns);

    return r_DONE;
}

void base_ns(void)
{
    log_debug(ZONE,"base_ns loading...\n");

    register_config("ns",base_ns_config,NULL);
}
