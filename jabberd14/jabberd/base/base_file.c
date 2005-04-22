/* --------------------------------------------------------------------------
 *
 *  jabberd 1.4.4 GPL - XMPP/Jabber server implementation
 *
 *  Copyrights
 *
 *  Portions created by or assigned to Jabber.com, Inc. are
 *  Copyright (C) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 *  information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 *  Portions Copyright (C) 1998-1999 Jeremie Miller.
 *
 *
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  Special exception for linking jabberd 1.4.4 GPL with OpenSSL:
 *
 *  In addition, as a special exception, you are allowed to link the code
 *  of jabberd 1.4.4 GPL with the OpenSSL library (or with modified versions
 *  of OpenSSL that use the same license as OpenSSL), and distribute linked
 *  combinations including the two. You must obey the GNU General Public
 *  License in all respects for all of the code used other than OpenSSL.
 *  If you modify this file, you may extend this exception to your version
 *  of the file, but you are not obligated to do so. If you do not wish
 *  to do so, delete this exception statement from your version.
 *
 * --------------------------------------------------------------------------*/

#include "jabberd.h"

result base_file_deliver(instance id, dpacket p, void* arg)
{
    FILE* f = (FILE*)arg;
    char* message = NULL;

    message = xmlnode_get_data(p->x);
    if (message == NULL)
    {
       log_debug2(ZONE, LOGT_STRANGE, "base_file_deliver error: no message available to print.\n");
       return r_ERR;
    }

    if (fprintf(f,"%s\n", message) == EOF)
    {
        log_debug2(ZONE, LOGT_IO, "base_file_deliver error: error writing to file(%d).\n", errno);
        return r_ERR;
    }
    fflush(f);

    /* Release the packet */
    pool_free(p->p);
    return r_DONE;    
}

void _base_file_shutdown(void *arg)
{
    FILE *filehandle=(FILE*)arg;
    fclose(filehandle);
}

result base_file_config(instance id, xmlnode x, void *arg)
{
    FILE* filehandle = NULL;
        
    if(id == NULL)
    {
        log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_file_config validating configuration");

        if (xmlnode_get_data(x) == NULL)
        {
            log_debug2(ZONE, LOGT_STRANGE|LOGT_CONFIG|LOGT_INIT, "base_file_config error: no filename provided.");
            xmlnode_put_attrib(x,"error","'file' tag must contain a filename to write to");
            return r_ERR;
        }
        return r_PASS;
    }

    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_file configuring instance %s",id->id);

    if(id->type != p_LOG)
    {
        log_alert(NULL,"ERROR in instance %s: <file>..</file> element only allowed in log sections", id->id);
        return r_ERR;
    }

    /* Attempt to open/create the file */
    filehandle = fopen(xmlnode_get_data(x), "a");
    if (filehandle == NULL)
    {
        log_alert(NULL,"base_file_config error: error opening file (%d): %s", errno, strerror(errno));
        return r_ERR;
    }

    /* Register a handler for this instance... */
    register_phandler(id, o_DELIVER, base_file_deliver, (void*)filehandle); 

    pool_cleanup(id->p, _base_file_shutdown, (void*)filehandle); 
    
    return r_DONE;
}

void base_file(void)
{
    log_debug2(ZONE, LOGT_INIT, "base_file loading...");
    register_config("file",base_file_config,NULL);
}
