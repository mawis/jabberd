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

result base_cache_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        log_debug(ZONE,"base_cache_config validating configuration\n");
        return r_PASS;
    }

    /* XXX uhgly, should figure out how to flag errors like this more consistently, during checking phase or something */
    if(id->type != p_XDB)
    {
        printf("ERROR: <cache>...</cache> element only allowed in xdb section\n");
        exit(1);
    }

    log_debug(ZONE,"base_cache_config performing configuration %s\n",xmlnode2str(x));

    return r_PASS;
}

void base_cache(void)
{
    log_debug(ZONE,"base_cache loading...\n");

    register_config("cache",base_cache_config,NULL);
}
