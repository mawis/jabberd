/*
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2007 Matthias Wimmer
 *
 * This file is part of jabberd14.
 *
 * This software is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

/**
 * @file base_to.cc
 * @brief forward received messages to a special destination address
 */

#include "jabberd.h"

static result base_to_deliver(instance id,dpacket p,void* arg) {
    char* log_data = xmlnode_get_data(p->x);
    char* subject;
    xmlnode message;

    if (log_data == NULL)
        return r_ERR;

    message = xmlnode_new_tag_ns("message", NULL, NS_SERVER);
    
    xmlnode_insert_cdata(xmlnode_insert_tag_ns(message, "body", NULL, NS_SERVER), log_data, -1);
    subject=spools(xmlnode_pool(message), "Log Packet from ", xmlnode_get_attrib_ns(p->x, "from", NULL), xmlnode_pool(message));
    xmlnode_insert_cdata(xmlnode_insert_tag_ns(message, "thread", NULL, NS_SERVER), shahash(subject), -1);
    xmlnode_insert_cdata(xmlnode_insert_tag_ns(message, "subject", NULL, NS_SERVER), subject, -1);
    xmlnode_put_attrib_ns(message, "from", NULL, NULL, xmlnode_get_attrib_ns(p->x, "from", NULL));
    xmlnode_put_attrib_ns(message, "to", NULL, NULL, (char*)arg);

    deliver(dpacket_new(message), id);
    pool_free(p->p);

    return r_DONE;
}

static result base_to_config(instance id, xmlnode x, void *arg) {
    if (id == NULL) {
        jid j = jid_new(xmlnode_pool(x), xmlnode_get_data(x));

        log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_to_config validating configuration\n");
        if (j == NULL) {
            xmlnode_put_attrib_ns(x, "error", NULL, NULL, "'to' tag must contain a jid to send log data to");
            log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "Invalid Configuration for base_to");
            return r_ERR;
        }
        return r_PASS;
    }

    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_to configuring instance %s", id->id);

    if (id->type != p_LOG) {
        log_alert(NULL, "ERROR in instance %s: <to>..</to> element only allowed in log sections", id->id);
        return r_ERR;
    }

    register_phandler(id, o_DELIVER, base_to_deliver, (void*)xmlnode_get_data(x));

    return r_DONE;
}

/**
 * register the to base handler
 *
 * @param p memory pool used to register the configuration handler, must be available for the livetime of jabberd
 */
void base_to(pool p) {
    log_debug2(ZONE, LOGT_INIT, "base_to loading...");
    register_config(p, "to",base_to_config,NULL);
}
