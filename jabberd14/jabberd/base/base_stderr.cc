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
 * @file base_stderr.cc
 * @brief write incoming packets to stderr (used to dump log messages)
 */

#include "jabberd.h"

static result base_stderr_display(instance i, dpacket p, void* args) {   
    char* message = NULL;
    
    /* Get the raw data from the packet */
    message = xmlnode_get_data(p->x);

    if (message == NULL) {
        log_debug2(ZONE, LOGT_STRANGE, "base_stderr_deliver: no message available to print.");
        return r_ERR;
    }

    /* We know message is non-null so fprintf is okay. */
    fprintf(stderr, "%s\n", message);

    pool_free(p->p);
    return r_DONE;
}

static result base_stderr_config(instance id, xmlnode x, void *arg) {
    if (id == NULL)
        return r_PASS;

    if (id->type != p_LOG) {
        log_alert(NULL, "ERROR in instance %s: <stderr/> element only allowed in log sections", id->id);
        return r_ERR;
    }

    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_stderr configuring instance %s",id->id);

    /* Register the handler, for this instance */
    register_phandler(id, o_DELIVER, base_stderr_display, NULL);

    return r_DONE;
}

/**
 * register the stderr base handler
 *
 * @param p memory pool used to register the configuration handler, must be available for the livetime of jabberd
 */
void base_stderr(pool p) {
    log_debug2(ZONE, LOGT_INIT, "base_stderr loading...");
    register_config(p, "stderr", base_stderr_config, NULL);
}
