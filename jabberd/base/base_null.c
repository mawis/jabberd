/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "JOSL").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the JOSL. You
 * may obtain a copy of the JOSL at http://www.jabber.org/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the JOSL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the JOSL
 * for the specific language governing rights and limitations under the
 * JOSL.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 or later (the "GPL"), in which case
 * the provisions of the GPL are applicable instead of those above.  If you
 * wish to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the JOSL,
 * indicate your decision by deleting the provisions above and replace them
 * with the notice and other provisions required by the GPL.  If you do not
 * delete the provisions above, a recipient may use your version of this file
 * under either the JOSL or the GPL. 
 * 
 * 
 * --------------------------------------------------------------------------*/

/**
 * @file base_null.c
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
