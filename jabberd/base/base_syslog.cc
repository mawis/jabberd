/*
 * Copyrights
 * 
 * Copyright (c) 2006-2007 Matthias Wimmer
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
 * @file base_syslog.cc
 * @brief write received packets to syslog (used for logging)
 */

#include "jabberd.h"

#ifdef HAVE_SYSLOG

#include <syslog.h>

static result base_syslog_deliver(instance id, dpacket p, void* arg) {
    int* facility = static_cast<int*>(arg);
    char* message = NULL;
    char* type_s = NULL;
    int type;

    message = xmlnode_get_data(p->x);
    if (message == NULL) {
       log_debug2(ZONE, LOGT_STRANGE, "base_syslog_deliver error: no message available to log.");
       return r_ERR;
    }

    type_s = xmlnode_get_attrib_ns(p->x, "type", NULL);
    if (type_s == NULL) {
	log_debug2(ZONE, LOGT_STRANGE, "base_syslog_deliver error: no type attribute.");
	return r_ERR;
    }

    type = log_get_level(type_s);
    if (type == -1)
	type = LOG_INFO;

    syslog(*facility|type, "%s", message);
    
    /* Release the packet */
    pool_free(p->p);
    return r_DONE;    
}

static result base_syslog_config(instance id, xmlnode x, void *arg) {
    int* facility = NULL;
    char *facility_str = NULL;

    if (id == NULL) {
        log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_syslog_config validating configuration");

        if (xmlnode_get_data(x) == NULL) {
            log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_syslog_config error: no facility provided");
            xmlnode_put_attrib_ns(x,"error", NULL, NULL, "'syslog' tag must contain a facility (use daemon, local0, ... local7)");
            return r_ERR;
        }
        return r_PASS;
    }

    log_debug2(ZONE, LOGT_CONFIG|LOGT_INIT, "base_syslog configuring instance %s",id->id);

    if (id->type != p_LOG) {
        log_alert(NULL,"ERROR in instance %s: <syslog>..</syslog> element only allowed in log sections", id->id);
        return r_ERR;
    }

    // allocate memory for the facility
    facility = static_cast<int*>(pmalloco(id->p, sizeof(int)));

    /* check which facility to use */
    facility_str = xmlnode_get_data(x);
    *facility = log_get_facility(facility_str);

    if (*facility == -1) {
	log_alert(NULL, "base_syslog_config error: unknown syslog facility: %s", facility_str);
	return r_ERR;
    }

    /* Register a handler for this instance... */
    register_phandler(id, o_DELIVER, base_syslog_deliver, facility); 

    return r_DONE;
}
#else
result base_syslog_config(instance id, xmlnode x, void *arg) {
    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_syslog_config error: jabberd compiled without syslog support.");
    xmlnode_put_attrib_ns(x, "error", NULL, NULL, PACKAGE " compiled without syslog support");
    return r_ERR;
}
#endif

/**
 * register the syslog base handler
 *
 * @param p memory pool used to register the configuration handler, must be available for the livetime of jabberd
 */
void base_syslog(pool p) {
    log_debug2(ZONE, LOGT_INIT, "base_syslog loading...");
    register_config(p, "syslog",base_syslog_config,NULL);
}
