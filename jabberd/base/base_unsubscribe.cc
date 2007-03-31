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
 * @file base_unsubscribe.cc
 * @brief base module base_unsubscribe: bounces messages and iqs, on receiving presences it sends unsubscribes
 *
 * This module is intended to be used, if the administrator of a server
 * discovers, that users of his server still have contacts on their rosters
 * for which there is no server anymore. Instead of getting the logging messages
 * telling about delivery failures, the admin can automatically create unsubscribes
 * to remove the contacts from the users' rosters and create bounces for other
 * stanzas.
 */

#include "jabberd.h"

/**
 * generate and send unsubscribe/unsubscribed packets
 *
 * @param id the instance we are running in
 * @param replied_stanza the stanza where sender and recipient address can be get from
 * @param type of reply to generate, either "unsubscribe" or "unsubscribed"
 */
static void base_unsubscribe_bounce_presence(instance id, xmlnode replied_stanza, const char* type) {
    xmlnode reply = NULL;
    const char *from = xmlnode_get_attrib_ns(replied_stanza, "to", NULL);
    const char *to = xmlnode_get_attrib_ns(replied_stanza, "from", NULL);

    reply = xmlnode_new_tag_ns("presence", NULL, NS_SERVER);
    xmlnode_put_attrib_ns(reply, "from", NULL, NULL, from);
    xmlnode_put_attrib_ns(reply, "to", NULL, NULL, to);
    xmlnode_put_attrib_ns(reply, "type", NULL, NULL, type);
    deliver(dpacket_new(reply), id);
    /* deliver() already freed the pool of the reply xmlnode ... */

    log_notice(id->id, "sent %s to %s for %s", type, to, from);
}

/**
 * handle stanza/packet deliveries to the base_unsubscribe module
 *
 * @param id the instance that handles the packet
 * @param p the packet to be handled
 * @param arg bounce reason (char *)
 * @return r_ERR on error, r_DONE if the packet is handled
 */
static result base_unsubscribe_deliver(instance id, dpacket p, void* arg) {
    jpacket packet_to_handle = NULL;

    /* check the params */
    if (id == NULL || p == NULL) {
	return r_ERR;
    }

    /* make a packet, as it is easier to be handled */
    packet_to_handle = jpacket_new(p->x);

    /* different actions base on packet types */
    switch (packet_to_handle->type) {
	case JPACKET_MESSAGE:
	case JPACKET_IQ:
	    deliver_fail(p, arg ? static_cast<char*>(arg) : messages_get(xmlnode_get_lang(p->x), N_("Destination blocked by server administrator")));
	    return r_DONE;
	case JPACKET_PRESENCE:
	    switch (packet_to_handle->subtype) {
		/* we got presence -> unsubscribe */
		case JPACKET__AVAILABLE:
		case JPACKET__INVISIBLE:
		    base_unsubscribe_bounce_presence(id, p->x, "unsubscribe");
		    break;
		/* we got probes -> unsubscribed */
		case JPACKET__PROBE:
		    base_unsubscribe_bounce_presence(id, p->x, "unsubscribed");
		    break;
	    }
	    break;
	case JPACKET_S10N:
	    /* deny subscription requests */
	    if (j_strcmp(xmlnode_get_attrib_ns(p->x, "type", NULL), "subscribe") == 0) {
		base_unsubscribe_bounce_presence(id, p->x, "unsubscribed");
	    }
	    break;
    }

    /* we did not bounce or deliver the packet we got, free it */
    pool_free(p->p);
    return r_DONE;
}

/**
 * configuration handling
 *
 * @param id the instance to handle the configuration for, NULL for only validating the configuration
 * @param x the <unsubscribe/> element that has to be processed
 * @param arg unused/ignored
 * @return r_ERR on error, r_PASS on success
 */
static result base_unsubscribe_config(instance id, xmlnode x, void *arg) {
    /* nothing has to be done for configuration validation */
    if (id == NULL) {
        return r_PASS;
    }

    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_unsubscribe configuring instance %s", id->id);

    if (id->type != p_NORM) {
        log_alert(NULL, "ERROR in instance %s: <unsubscribe>..</unsubscribe> element only allowed in service sections", id->id);
        return r_ERR;
    }

    register_phandler(id, o_DELIVER, base_unsubscribe_deliver, (void*)xmlnode_get_data(x));

    return r_DONE;
}

/**
 * load the base_unsubscribe base module by registering a configuration handler for &lt;unsubscribe/&gt;
 *
 * @param p memory pool used to register the configuration handler, must be available for the livetime of jabberd
 */
void base_unsubscribe(pool p) {
    log_debug2(ZONE, LOGT_INIT, "base_unsubscribe loading...");
    register_config(p, "unsubscribe",base_unsubscribe_config,NULL);
}
