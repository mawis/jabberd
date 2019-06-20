/*
 * Copyrights
 * 
 * Copyright (c) 2007 Matthias Wimmer
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
 * @file instance_base.cc
 * @brief OOP interface of jabberd14 for components
 */

#include <jabberd.h>
#include <stdexcept>

namespace xmppd {
    instance_base::instance_base(instance i, xmlnode x) : i(i), current_heartbeat_frequency(0), requested_heartbeat_frequency(0) {
	// register our packet handler with the server
	::register_phandler(i, o_DELIVER, instance_base::phandler_helper, this);

	// create our logger
	try {
	    logger = std::shared_ptr<logging>(new logging(get_instance_id()));
	} catch (std::domain_error) {
	    logger = std::shared_ptr<logging>(new logging("-internal.invalid"));
	}
    }

    result instance_base::on_packet(dpacket dp) {
	// sanity check
	if (dp == NULL)
	    return r_ERR;

	switch (dp->type) {
	    case p_NORM:
		return on_stanza_packet(dp);
	    case p_XDB:
		return on_xdb_packet(dp);
	    case p_LOG:
		return on_log_packet(dp);
	    case p_ROUTE:
		return on_route_packet(dp);
	    default:
		deliver_fail(dp, N_("This component does not know the type of packet."));
		return r_DONE;
	}
    }

    result instance_base::on_stanza_packet(dpacket dp) {
	::jpacket p = ::jpacket_new(dp->x);

	switch (p->type) {
	    case JPACKET_MESSAGE:
		return on_message_stanza(p);
	    case JPACKET_PRESENCE:
		return on_presence_stanza(p);
	    case JPACKET_IQ:
		return on_iq_stanza(p);
	    case JPACKET_S10N:
		return on_subscription_stanza(p);
	    default:
		deliver_fail(dp, N_("The stanza type could not be determined."));
		return r_DONE;
	}
    }

    result instance_base::on_message_stanza(jpacket p) {
	bounce_stanza(p->x, XTERROR_NOTIMPL);
	return r_DONE;
    }

    result instance_base::on_presence_stanza(jpacket p) {
	bounce_stanza(p->x, XTERROR_NOTIMPL);
	return r_DONE;
    }

    result instance_base::on_iq_stanza(jpacket p) {
	bounce_stanza(p->x, XTERROR_NOTIMPL);
	return r_DONE;
    }

    result instance_base::on_subscription_stanza(jpacket p) {
	// we cannot bounce subscription stanzas
	// XXX send unsubscribe instead
	xmlnode_free(p->x);
	return r_DONE;
    }

    result instance_base::on_log_packet(dpacket dp) {
	deliver_fail(dp, N_("This component does not handle log packets"));
	return r_DONE;
    }

    result instance_base::on_xdb_packet(dpacket dp) {
	deliver_fail(dp, N_("This component does not handle xdb packets"));
	return r_DONE;
    }

    result instance_base::on_route_packet(dpacket dp) {
	deliver_fail(dp, N_("This component does not handle routed packets"));
	return r_DONE;
    }

    void instance_base::on_heartbeat() {
    }

    result instance_base::beathandler_wrapper() {
	// call our handler if we do not want to stop heartbeat
	if (requested_heartbeat_frequency > 0) {
	    on_heartbeat();
	}

	// do we have to change the heartbeat frequency?
	if (current_heartbeat_frequency != requested_heartbeat_frequency) {
	    // if heartbeat is still requested, request it with new frequency
	    if (requested_heartbeat_frequency > 0) {
		::register_beat(requested_heartbeat_frequency, instance_base::beathandler_helper, this);
	    }

	    // updated the current frequency
	    current_heartbeat_frequency = requested_heartbeat_frequency;

	    // stop current heartbeat
	    return r_UNREG;
	}

	// keep getting events
	return r_DONE;
    }

    void instance_base::set_heartbeat_interval(int interval) {
	// set the requested frequency
	requested_heartbeat_frequency = interval;

	// do we have to register the heartbeat?
	if (current_heartbeat_frequency == 0 && requested_heartbeat_frequency > 0) {
	    ::register_beat(requested_heartbeat_frequency, instance_base::beathandler_helper, this);
	}
    }

    void instance_base::deliver(dpacket p) {
	::deliver(p, i);
    }

    void instance_base::deliver(xmlnode x) {
	::deliver(::dpacket_new(x), i);
    }

    void instance_base::deliver_fail(dpacket p, const std::string& reason_text) {
	::deliver_fail(p, reason_text.c_str());
    }

    instance_base::instance_base(instance_base& ref) {
	throw std::invalid_argument("You cannot copy an instance");
    }

    result instance_base::phandler_helper(instance id, dpacket p, void* arg) {
	return static_cast<instance_base*>(arg)->on_packet(p);
    }

    result instance_base::beathandler_helper(void* arg) {
	static_cast<instance_base*>(arg)->on_heartbeat();
        return r_DONE;
    }

    void instance_base::bounce_stanza(xmlnode x, xterror xterr) {
	// format the bounce
	jutil_error_xmpp(x, xterr);

	// send the bounce
	deliver(x);
    }

    std::string instance_base::get_instance_id() {
	if (i->id == NULL)
	    throw std::domain_error("instance has no id");
	return i->id;
    }

    logmessage instance_base::log(loglevel level) {
	return logger->level(level);
    }

    xmlnode instance_base::get_instance_config() {
	// search for the first child element of the service element in a different namespace
        for(xmlnode x = xmlnode_get_firstchild(i->x); x; x = xmlnode_get_nextsibling(x)) {
	    // skip elements in the NS_JABBERD_CONFIGFILE namespace
	    if (j_strcmp(xmlnode_get_namespace(x), NS_JABBERD_CONFIGFILE) == 0)
		continue;

	    // only elements
	    if (xmlnode_get_type(x) != NTYPE_TAG)
		continue;

	    // we found it
	    return x;
        }

	// no configuration element found
	return NULL;
    }
};
