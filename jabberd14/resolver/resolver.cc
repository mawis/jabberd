/*
 * Copyrights
 * 
 * Copyright (c) 2008/2009 Matthias Wimmer
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
 * @file resolver.cc
 * @brief This implements a resolver by accessing a lwresd
 *
 * This is a module for xmppd that implements a resolver that resolves DNS names by delegating the actual requests to a lwresd.
 */

#include <resolver.h>

namespace xmppd {
    namespace resolver {
	resolver::resolver(instance i, xmlnode x) : instance_base(i, x), lwresd_socket(NULL), queue_timeout(60), lwresd_host("localhost"), lwresd_service("921") {
	    configurate();

	    open_lwresd_socket();
	}

	void resolver::open_lwresd_socket() {
	    int udp_socket = make_netsocket2(lwresd_service, lwresd_host, NETSOCKET_UDP);

	    lwresd_socket = mio_new(udp_socket, mio_callback, this, MIO_CONNECT_RAW);
	}

	void resolver::mio_callback(mio m, int state, void* arg, xmlnode x, char* buffer, int bufsz) {
	    // sanity check
	    if (!arg) {
		return;
	    }

	    // make everything a bit nicer and call mio_event
	    static_cast<resolver*>(arg)->mio_event(m, state, buffer ? std::string(buffer, bufsz) : std::string());
	}

	void resolver::mio_event(mio m, int state, std::string const& buffer) {
	    switch (state) {
		case MIO_CLOSED:
		    mio_event_closed(m);
		    break;
		case MIO_BUFFER:
		    mio_event_buffer(m, buffer);
		    break;
		case MIO_ERROR:
		default:
		    mio_event_error(m);
	    }
	}

	void resolver::mio_event_buffer(mio m, std::string const& buffer) {
	    // parse the result
	    std::istringstream buffer_stream(buffer);
	    xmppd::lwresc::lwresult query_result(buffer_stream);

	    // make sure the listener does not get deleted while it is running
	    xmppd::xhash< std::shared_ptr<resolver_job> > pending_jobs_lock = pending_jobs;

	    // send the signal for this result
	    uint32_t serial = query_result.getSerial();
	    std::map<uint32_t, std::pair<time_t, sigc::signal<void, xmppd::lwresc::lwresult const&> > >::iterator result_listener = result_listeners.find(serial);
	    if (result_listener != result_listeners.end()) {
		result_listener->second.second.emit(query_result);
		result_listeners.erase(result_listener);
	    }

	}

	void resolver::mio_event_closed(mio m) {
	}

	void resolver::mio_event_error(mio m) {
	}

	std::list<resend_service> const& resolver::get_resend_services() {
	    return resend_services;
	}

	void resolver::configurate() {
	    // get the configuration
	    xmlnode config = get_instance_config();

	    // get and iterate the resend childs
	    xht namespaces = xhash_new(3);
	    xhash_put(namespaces, "dnsrv", const_cast<char*>(NS_JABBERD_CONFIG_DNSRV));
	    xmlnode_vector resend_elements = xmlnode_get_tags(config, "dnsrv:resend", namespaces);
	    for (xmlnode_vector::iterator p = resend_elements.begin(); p != resend_elements.end(); ++p) {
		try {
		    resend_services.push_back(resend_service(*p));
		} catch (std::invalid_argument) {
		}
	    }

	    // get the queue timeout (time we are waiting to a DNS resolving result
	    char const* queuetimeout_attrib = xmlnode_get_attrib_ns(config, "queuetimeout", NULL);
	    if (queuetimeout_attrib) {
		std::istringstream queuetimeout_stream(queuetimeout_attrib);
		queuetimeout_stream >> queue_timeout;

		// a timeout of less than 10 seconds does not seem to make sense
		if (queue_timeout < 10) {
		    queue_timeout = 10;
		}
	    } else {
		queue_timeout = 60;
	    }
	    set_heartbeat_interval(queue_timeout);

	    // free temp resources
	    xhash_free(namespaces);
	    namespaces = NULL;
	}

	void resolver::send_query(xmppd::lwresc::lwquery const& query) {
	    // get binary representation of the query
	    std::ostringstream query_bin;
	    query_bin << query;

	    // send it
	    mio_write(lwresd_socket, NULL, query_bin.str().c_str(), query_bin.str().length());
	}

	sigc::connection resolver::register_result_callback(uint32_t serial, sigc::signal<void, xmppd::lwresc::lwresult const&>::slot_type const& callback) {
	    if (result_listeners.find(serial) == result_listeners.end()) {
		result_listeners[serial] = std::pair<time_t, sigc::signal<void, xmppd::lwresc::lwresult const&> >(std::time(NULL), sigc::signal<void, xmppd::lwresc::lwresult const&>());
	    }

	    return result_listeners[serial].second.connect(callback);
	}

	result resolver::on_stanza_packet(dpacket dp) {
	    // sanity check
	    if (!dp || !dp->host)
		return r_ERR;

	    // check if the packet already has been resolved (in the case of looping packets)
	    if (xmlnode_get_attrib_ns(dp->x, "ip", NULL) || xmlnode_get_attrib_ns(dp->x, "iperror", NULL)) {
		char const* packet_type = xmlnode_get_attrib_ns(dp->x, "type", NULL);

		// drop type='error', bounce everything else
		if (packet_type && Glib::ustring(packet_type) == "error") {
		    log(xmppd::warn) << "Looping DNS request. Dropped: " << xmlnode_serialize_string(dp->x, xmppd::ns_decl_list(), 0);
		    xmlnode_free(dp->x);
		} else {
		    deliver_fail(dp, N_("Looping DNS request. Dropped."));
		}

		return r_DONE;
	    }

	    // is there already a resolve request pending for this domain? Just add to queue for this resolving
	    if (pending_jobs.find(dp->host) != pending_jobs.end()) {
		pending_jobs[dp->host]->add_packet(dp);
		return r_DONE;
	    }

	    // store the packet, so that we can forward it when it has been resolved, and start resolving
	    pending_jobs[dp->host] = std::shared_ptr<resolver_job>(new resolver_job(*this, dp));
	    log(xmppd::notice) << "Created new resolver job: " << *(pending_jobs[dp->host]);
	    pending_jobs[dp->host]->register_result_callback(sigc::mem_fun(*this, &xmppd::resolver::resolver::handle_completed_job));
	    return r_DONE;
	}

	result resolver::on_route_packet(dpacket dp) {
	    // only packets addressed to us directly (no default route) are accepted as routed packets
	    if (!dp->host || get_instance_id() != dp->host) {
		return instance_base::on_route_packet(dp);
	    }

	    // the routed packet has to have a to attribute
	    jid to = jid_new(dp->p, xmlnode_get_attrib_ns(xmlnode_get_firstchild(dp->x), "to", NULL));
	    if (to == NULL) {
		return r_ERR;
	    }

	    // unpack the routed packet and process it
	    dp->x = xmlnode_get_firstchild(dp->x);
	    dp->id = to;
	    dp->host = pstrdup(dp->p, to->get_domain().c_str());
	    return on_stanza_packet(dp);
	}

	void resolver::resend_packet(xmlnode pkt, Glib::ustring ips, Glib::ustring to) {
	    if (ips.empty()) {
		jutil_error_xmpp(pkt, (xterror){502, N_("Unable to resolve hostname."), "wait", "service-unavailable"});
		xmlnode_put_attrib_ns(pkt, "iperror", NULL, NULL, "");
	    } else {
		char const* dnsresultto = xmlnode_get_attrib_ns(pkt, "dnsqueryby", NULL);
		if (!dnsresultto) {
		    dnsresultto = to.c_str();
		}

		pkt = xmlnode_wrap_ns(pkt, "route", NULL, NS_SERVER);
		xmlnode_put_attrib_ns(pkt, "to", NULL, NULL, dnsresultto);
		xmlnode_put_attrib_ns(pkt, "ip", NULL, NULL, ips.c_str());

		// XXX
		if (std::string("verify") == xmlnode_get_localname(pkt) && std::string(NS_DIALBACK) == xmlnode_get_namespace(pkt)) {
		    log(xmppd::notice) << "DB resend: " << xmlnode_serialize_string(pkt, xmppd::ns_decl_list(), 0);
		}
	    }
	    deliver(pkt);
	}

	void resolver::handle_completed_job(resolver_job& job) {
	    // delete the job from the pending jobs list
	    char const* host = job.get_packets().front()->host;
	    pending_jobs.erase(host);

	    // get the packets
	    std::list<dpacket> const& packets = job.get_packets();

	    // get the resend destination
	    Glib::ustring resend_host = job.get_resend_host().full();

	    // get the resolved ips
	    Glib::ustring ips = job.get_result();

	    log(xmppd::notice) << (ips.empty() ? "Finished resolver job without result: " : "Finished resolver job: ") << job;

	    // resend the packets
	    for (std::list<dpacket>::const_iterator p = packets.begin(); p != packets.end(); ++p) {
		resend_packet((*p)->x, ips, resend_host);
	    }
	}
    }
}

/**
 * init and register the resolver component in the server
 *
 * @todo care for destructing the resolver instance on shutdown
 *
 * @param i the jabber server's data about this instance
 * @param x xmlnode of this instances configuration (???)
 */
extern "C" void resolver(instance i, xmlnode x) {
    new xmppd::resolver::resolver(i, x);
}
