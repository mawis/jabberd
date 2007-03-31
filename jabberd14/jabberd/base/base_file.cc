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
 * @file base_file.cc
 * @brief write received data to a file (used to do logging)
 */

#include "jabberd.h"

static result base_file_deliver(instance id, dpacket p, void* arg) {
    FILE* f = (FILE*)arg;
    char* message = NULL;

    message = xmlnode_get_data(p->x);
    if (message == NULL) {
       log_debug2(ZONE, LOGT_STRANGE, "base_file_deliver error: no message available to print.\n");
       return r_ERR;
    }

    if (fprintf(f,"%s\n", message) == EOF) {
        log_debug2(ZONE, LOGT_IO, "base_file_deliver error: error writing to file(%d).\n", errno);
        return r_ERR;
    }
    fflush(f);

    /* Release the packet */
    pool_free(p->p);
    return r_DONE;    
}

static void _base_file_shutdown(void *arg) {
    FILE *filehandle=(FILE*)arg;
    fclose(filehandle);
}

static result base_file_config(instance id, xmlnode x, void *arg) {
    FILE* filehandle = NULL;
        
    if (id == NULL) {
        log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_file_config validating configuration");

        if (xmlnode_get_data(x) == NULL) {
            log_debug2(ZONE, LOGT_STRANGE|LOGT_CONFIG|LOGT_INIT, "base_file_config error: no filename provided.");
            xmlnode_put_attrib_ns(x, "error", NULL, NULL, "'file' tag must contain a filename to write to");
            return r_ERR;
        }
        return r_PASS;
    }

    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_file configuring instance %s",id->id);

    if (id->type != p_LOG) {
        log_alert(NULL, "ERROR in instance %s: <file>..</file> element only allowed in log sections", id->id);
        return r_ERR;
    }

    /* Attempt to open/create the file */
    filehandle = fopen(xmlnode_get_data(x), "a");
    if (filehandle == NULL) {
        log_alert(NULL, "base_file_config error: error opening file (%d): %s", errno, strerror(errno));
        return r_ERR;
    }

    /* Register a handler for this instance... */
    register_phandler(id, o_DELIVER, base_file_deliver, (void*)filehandle); 

    pool_cleanup(id->p, _base_file_shutdown, (void*)filehandle); 
    
    return r_DONE;
}

/**
 * register the file base handler
 *
 * @param p memory pool used to register the configuration handler, must be available for the livetime of jabberd
 */
void base_file(pool p) {
    log_debug2(ZONE, LOGT_INIT, "base_file loading...");
    register_config(p, "file",base_file_config,NULL);
}
