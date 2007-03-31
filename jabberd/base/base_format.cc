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
 * @file base_format.cc
 * @brief reformat stanzas and let them pass to the next base handler (used to format log messages)
 */

#include "jabberd.h"

static result base_format_modify(instance id, dpacket p, void *arg) {
    char  *cur, *nxt, *f;
    pool  sp;
    spool log_result;

    if(id == NULL || p == NULL) 
        return r_ERR;

    /*  base format params:
        %h: host
        %t: type
        %d: date
        %s: body
    */

    sp=pool_new();

    f = pstrdup(sp, (char*)arg);
    log_result = spool_new(sp);

    cur = f;
    nxt = strchr(f, '%');
    
    if (nxt == NULL)
        spooler(log_result, f, log_result);
    
    while (nxt != NULL) {
        nxt[0] = '\0'; 
        
        if(cur != nxt)
            spooler(log_result, cur, log_result);
        
        nxt++;
        
        switch(nxt[0]) {
	    case 'h':
		spooler(log_result, xmlnode_get_attrib_ns(p->x, "from", NULL), log_result);
		break;
	    case 't':
		spooler(log_result, xmlnode_get_attrib_ns(p->x, "type", NULL), log_result);
		break;
	    case 'd':
		spooler(log_result, jutil_timestamp(), log_result);
		break;
	    case 's':
		spooler(log_result, xmlnode_get_data(p->x), log_result);
		break;
	    default:
		log_debug2(ZONE, LOGT_CONFIG|LOGT_STRANGE, "Invalid argument: %s", nxt[0]);
        }
        
        cur = ++nxt;
        nxt = strchr(cur, '%');
    }

    xmlnode_hide(xmlnode_get_firstchild(p->x));
    xmlnode_insert_cdata(p->x, spool_print(log_result), -1);

    pool_free(sp);
    return r_PASS;
}

static result base_format_config(instance id, xmlnode x, void *arg) {
    if (id == NULL) {
        log_debug2(ZONE, LOGT_CONFIG|LOGT_INIT, "base_format_config validating configuration");
        if (xmlnode_get_data(x) == NULL) {
            log_debug2(ZONE, LOGT_CONFIG|LOGT_INIT|LOGT_STRANGE, "base_format invald format");
            xmlnode_put_attrib_ns(x, "error", NULL, NULL, "'format' tag must contain a format string:\nUse %h to insert Hostname\nUse %t to insert Type of Log (notice,warn,alert)\nUse %d to insert Timestamp\nUse %s to insert the body of the message\n\nExample: '[%t] - %h - %d: %s'");
            return r_ERR;
        }
        return r_PASS;
    }
    
    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_format configuring instance %s ", id->id);

    if (id->type != p_LOG) {
        log_alert(NULL, "ERROR in instance %s: <format>..</format> element only allowed in log sections", id->id);
        return r_ERR;
    }

    register_phandler(id, o_PREDELIVER, base_format_modify, (void*)xmlnode_get_data(x));

    return r_DONE;
}

/**
 * register the format base handler
 *
 * @param p memory pool used for the registration of the config handler, must be available for the livetime of jabberd
 */
void base_format(pool p) {
    log_debug2(ZONE, LOGT_INIT, "base_format loading...");
    register_config(p, "format",base_format_config,NULL);
}
