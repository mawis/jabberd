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

result base_file_deliver(instance id, dpacket p, void* arg)
{
    FILE* f = (FILE*)arg;
    char* message = NULL;

    message = xmlnode_get_data(p->x);
    if (message == NULL)
    {
       log_debug(ZONE,"base_file_deliver error: no message available to print.\n");
       return r_ERR;
    }
    
    if (fprintf(f,"%s\n", message) == EOF)
    {
        log_debug(ZONE,"base_file_deliver error: error writing to file(%d).\n", errno);
        return r_ERR;
    }
    fflush(f);

    /* Release the packet */
    pool_free(p->p);
    return r_DONE;    
}

result base_file_config(instance id, xmlnode x, void *arg)
{
    FILE* filehandle = NULL;
        
    if(id == NULL)
    {
        if (xmlnode_get_data(x) == NULL)
        {
            log_debug(ZONE,"base_file_config error: no filename provided.\n");
            return r_ERR;
        }
        log_debug(ZONE,"base_file_config validating configuration\n");
        return r_PASS;
    }

    /* XXX this is an ugly hack, but it's better than a bad config */
    /* XXX needs to be a way to validate this in the checking phase */
    if(id->type!=p_LOG)
    {
        log_debug(ZONE,"<file>..</file> element only allowed in log sections");
        return r_ERR;
    }

    /* Attempt to open/create the file */
    filehandle = fopen(xmlnode_get_data(x), "a");
    if (filehandle == NULL)
    {
        log_debug(ZONE,"base_file_config error: error opening file (%d)\n", errno);
        return r_ERR;
    }

    /* Register a handler for this instance... */
    register_phandler(id, o_DELIVER, base_file_deliver, (void*)filehandle); 
    
    log_debug(ZONE,"base_file_config performing configuration %s\n",xmlnode2str(x));
    return r_DONE;
}

void base_file(void)
{
    log_debug(ZONE,"base_file loading...\n");

    register_config("file",base_file_config,NULL);
}
