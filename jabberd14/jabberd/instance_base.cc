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
	::register_phandler(i, o_DELIVER, instance_base::phandler_helper, this);
    }

    result instance_base::on_packet(dpacket dp) {
	return r_UNREG;
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
	static_cast<instance_base*>(arg)->on_packet(p);
    }

    result instance_base::beathandler_helper(void* arg) {
	static_cast<instance_base*>(arg)->on_heartbeat();
    }
};
