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

result base_to_deliver(instance id,dpacket p,void* arg)
{
    char* log_data=xmlnode_get_data(p->x);
    xmlnode message;

    if(log_data==NULL)
        return r_ERR;

    message=xmlnode_new_tag("message");
    xmlnode_insert_cdata(message,log_data,-1);
    xmlnode_put_attrib(message,"from",xmlnode_get_attrib(p->x,"from"));
    xmlnode_put_attrib(message,"to",(char*)arg);
    deliver(dpacket_new(message),id);

    pool_free(p->p);
    return r_DONE;
}

result base_to_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        log_debug(ZONE,"base_to_config validating configuration\n");
        if(xmlnode_get_data(x)==NULL)
        {
            log_error(ZONE,"Invalid Configuration for base_to");
            return r_ERR;
        }
        return r_PASS;
    }

    register_phandler(id,o_DELIVER,base_to_deliver,(void*)strdup(xmlnode_get_data(x)));
    return r_DONE;
}

void base_to(void)
{
    log_debug(ZONE,"base_to loading...\n");

    register_config("to",base_to_config,NULL);
}
