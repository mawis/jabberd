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
    <host>hostname.org</host>
    <host>*.polld.isp.net</host> [the . flags any domain matching that]
    <host/>
*/

result base_host_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        log_debug(ZONE,"base_host_config validating configuration %s\n",xmlnode2str(x));
        return r_PASS;
    }

    log_debug(ZONE,"base_host_config registering host %s with section '%s'\n",xmlnode_get_data(x), id->id);
    register_instance(id, xmlnode_get_data(x));

    return r_PASS;
}

void base_host(void)
{
    log_debug(ZONE,"base_host loading...\n");

    register_config("host",base_host_config,NULL);
}
