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

result base_to_deliver(instance id,dpacket p,void* arg)
{
    char* log_data = xmlnode_get_data(p->x);
    char* subject;
    xmlnode message;

    if(log_data == NULL)
        return r_ERR;

    message = xmlnode_new_tag("message");
    
    xmlnode_insert_cdata(xmlnode_insert_tag(message,"body"), log_data, -1);
    subject=spools(xmlnode_pool(message), "Log Packet from ", xmlnode_get_attrib(p->x, "from"), xmlnode_pool(message));
    xmlnode_insert_cdata(xmlnode_insert_tag(message, "thread"), shahash(subject), -1);
    xmlnode_insert_cdata(xmlnode_insert_tag(message, "subject"), subject, -1);
    xmlnode_put_attrib(message, "from", xmlnode_get_attrib(p->x, "from"));
    xmlnode_put_attrib(message, "to", (char*)arg);

    deliver(dpacket_new(message), id);
    pool_free(p->p);

    return r_DONE;
}

result base_to_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        jid j = jid_new(xmlnode_pool(x), xmlnode_get_data(x));

        log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_to_config validating configuration\n");
        if(j == NULL)
        {
            xmlnode_put_attrib(x, "error", "'to' tag must contain a jid to send log data to");
            log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "Invalid Configuration for base_to");
            return r_ERR;
        }
        return r_PASS;
    }

    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_to configuring instance %s", id->id);

    if(id->type != p_LOG)
    {
        log_alert(NULL, "ERROR in instance %s: <to>..</to> element only allowed in log sections", id->id);
        return r_ERR;
    }

    register_phandler(id, o_DELIVER, base_to_deliver, (void*)xmlnode_get_data(x));

    return r_DONE;
}

void base_to(void)
{
    log_debug2(ZONE, LOGT_INIT, "base_to loading...");
    register_config("to",base_to_config,NULL);
}
