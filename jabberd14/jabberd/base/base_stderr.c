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

result base_stderr_display(instance i, dpacket p, void* args)
{   
    char* message = NULL;
    
    /* Get the raw data from the packet */
    message = xmlnode_get_data(p->x);

    if(message == NULL)
    {
        log_debug2(ZONE, LOGT_STRANGE, "base_stderr_deliver: no message available to print.");
        return r_ERR;
    }

    /* We know message is non-null so fprintf is okay. */
    fprintf(stderr, "%s\n", message);

    pool_free(p->p);
    return r_DONE;
}

result base_stderr_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
        return r_PASS;

    if(id->type != p_LOG)
    {
        log_alert(NULL, "ERROR in instance %s: <stderr/> element only allowed in log sections", id->id);
        return r_ERR;
    }

    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_stderr configuring instance %s",id->id);

    /* Register the handler, for this instance */
    register_phandler(id, o_DELIVER, base_stderr_display, NULL);

    return r_DONE;
}

void base_stderr(void)
{
    log_debug2(ZONE, LOGT_INIT, "base_stderr loading...");
    register_config("stderr", base_stderr_config, NULL);
}
