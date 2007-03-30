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
 * @file base.cc
 * @brief load all base handlers, register their configuration handlers
 */

/**
 * @dir base
 * @brief Contains the base handlers of jabberd14
 *
 * Jabberd14 is an XML router, that routes XML stanzas between the different base handlers. Some of these
 * base handlers (like the unsubscribe handler implemented in base_unsubscribe.c) handle packets themselves.
 * Other handlers (accept, connect, load, ...) implement interfaces, that can be used by components
 * to use the XML routing functionality.
 */

#include "jabberd.h"

void base_accept(pool p);
void base_connect(pool p);
void base_dir(pool p);
void base_file(pool p);
void base_format(pool p);
void base_to(pool p);
void base_stderr(pool p);
void base_stdout(pool p);
void base_syslog(pool p);
void base_unsubscribe(pool p);
void base_load(pool p);
void base_null(pool p);
void base_importspool(pool p);

/**
 * load all base modules
 *
 * @param p memory pool, that can be used to register the configuration handlers, must be available for the livetime of jabberd
 */
void base_init(pool p) {
    base_accept(p);
    base_connect(p);
    base_dir(p);
    base_file(p);
    base_format(p);
    base_load(p);
    base_null(p);
    base_stderr(p);
    base_stdout(p);
    base_syslog(p);
    base_to(p);
    base_unsubscribe(p);
    base_importspool(p);
}
