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

result base_logtype_filter(instance id, dpacket p, void* arg)
{
    char* comparisontype = (char*)arg;
    char* packettype     = xmlnode_get_attrib(p->x, "type");

    if (comparisontype == NULL || packettype == NULL)
    {
        /* FIXME: this might not be an error if <log>'s don't require a type */
        log_debug(ZONE,"base_logtype_filter error: invalid data; unable to filter.\n");
        return r_ERR;
    }

    /* If comparison fails, return ok..*/
    if (strcmp(packettype, comparisontype) == 0)
    {
        return r_PASS;
    }

    /* Otherwise, the filter failed */
    return r_ERR;
}

result base_logtype_config(instance id, xmlnode x, void *arg)
{
    char* name = NULL;
    name = xmlnode_get_name(x);
    if(id == NULL)
    {
        /* Ensure that the name of the tag is either "notice", "warn", or "alert" */
        if (strcmp(name, "notice") && strcmp(name, "warn") && strcmp(name, "alert"))
        {
            xmlnode_put_attrib(x,"error","Invalid log type filter requested");
            log_debug(ZONE,"base_logtype_config error: invalid log type filter requested (%s)\n", name);
            return r_ERR;
        }
        
        log_debug(ZONE,"base_logtype_config validating configuration\n");
        return r_PASS;
    }

    /* XXX this is an ugly hack, but it's better than a bad config */
    /* XXX needs to be a way to validate this in the checking phase */
    if(id->type!=p_LOG)
    {
        printf("ERROR: <notice/>,<warn/> and <alert/> elements only allowed in log sections\n");
        exit(1);
    }

    /* Register a conditional handler for this instance, passing the name
     * of the tag as an argument (for comparison in the filter op 
     */
    register_phandler(id, o_COND, base_logtype_filter, (void*)name);

    log_debug(ZONE,"base_logtype_config performing configuration %s\n",xmlnode2str(x));

    return r_PASS;
}

void base_logtype(void)
{
    log_debug(ZONE,"base_logtype loading...\n");

    register_config("notice",base_logtype_config,NULL);
    register_config("warn",base_logtype_config,NULL);
    register_config("alert",base_logtype_config,NULL);
}
