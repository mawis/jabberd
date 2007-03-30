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
 * @file base_null.cc
 * @brief implements a base handler (xml routing target), that drops all messages
 */

#include "jabberd.h"

/**
 * handler for the &lt;null/&gt; delivery target
 *
 * It just deletes packets
 *
 * @param i unused/ignored
 * @param p the packet to delete
 * @param arg unused/ignored
 * @return always r_DONE
 */
static result base_null_deliver(instance i, dpacket p, void* arg) {
    pool_free(p->p);
    return r_DONE;
}

/**
 * handler for the &lt;null/&gt; configuration element
 *
 * @param i the instance the element is in
 * @param x the configuration element
 * @param arg unused/ignored
 * @return r_DONE on success, r_PASS if no instance is given
 */
static result base_null_config(instance i, xmlnode x, void *arg) {
    if(i == NULL)
        return r_PASS;

    register_phandler(i, o_DELIVER, base_null_deliver, NULL);
    return r_DONE;
}

/**
 * initialize the XML delivery system
 *
 * @param p memory pool that can be used to register config handlers (must be available for the livetime of jabberd)
 */
void base_null(pool p) {
    register_config(p, "null", base_null_config, NULL);
}
