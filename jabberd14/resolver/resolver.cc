/*
 * Copyrights
 * 
 * Copyright (c) 2008 Matthias Wimmer
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
	    log_debug2(ZONE, LOGT_IO, "opening socket: service=%s, host=%s", lwresd_service.c_str(), lwresd_host.c_str());
	    int udp_socket = make_netsocket2(lwresd_service, lwresd_host, NETSOCKET_UDP);

	    log_debug2(ZONE, LOGT_IO, "netsocket is on fd %i", udp_socket);

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
	    log_debug2(ZONE, LOGT_IO, "sending %i bytes", query_bin.str().length());
	    mio_write(lwresd_socket, NULL, query_bin.str().c_str(), query_bin.str().length());
	}

	sigc::connection resolver::register_result_callback(uint32_t serial, sigc::signal<void, xmppd::lwresc::lwresult const&>::slot_type const& callback) {
	    if (result_listeners.find(serial) == result_listeners.end()) {
		result_listeners[serial] = std::pair<time_t, sigc::signal<void, xmppd::lwresc::lwresult const&> >(std::time(NULL), sigc::signal<void, xmppd::lwresc::lwresult const&>());
	    }

	    return result_listeners[serial].second.connect(callback);
	}

	resend_service::resend_service(xmlnode resend) : weight_sum(0) {
	    char const* service_attribute_value = xmlnode_get_attrib_ns(resend, "service", NULL);

	    // if there is a service attribute, keep it
	    if (service_attribute_value)
		service = service_attribute_value;

	    // check, get and iterate partial childs
	    xht namespaces = xhash_new(3);
	    xhash_put(namespaces, "dnsrv", const_cast<char*>(NS_JABBERD_CONFIG_DNSRV));
	    xmlnode_vector partial_elements = xmlnode_get_tags(resend, "dnsrv:partial", namespaces);
	    xhash_free(namespaces);
	    namespaces = NULL;
	    for (xmlnode_vector::iterator p = partial_elements.begin(); p != partial_elements.end(); ++p) {
		// get the weight for this partial destination
		char const* weight_attrib = xmlnode_get_attrib_ns(*p, "weight", NULL);
		int weight = 1;
		if (weight_attrib) {
		    std::istringstream weight_stream(weight_attrib);
		    weight_stream >> weight;
		}
		if (weight < 1)
		    weight = 1;

		// get the destination
		char const* resend_dest = xmlnode_get_data(*p);
		if (!resend_dest)
		    continue;
		try {
		    xmppd::jabberid resend_jid(resend_dest);

		    // keep
		    resend_hosts.push_back(std::pair<int, xmppd::jabberid>(weight, resend_jid));
		    weight_sum += weight;
		} catch (std::invalid_argument) {
		    continue;
		}

	    }

	    // if there where no partial childs, use the text() child of the <resend/> element
	    if (resend_hosts.empty()) {
		try {
		    char const* resend_dest = xmlnode_get_data(resend);
		    if (resend_dest) {
			xmppd::jabberid resend_jid(resend_dest);

			// keep
			resend_hosts.push_back(std::pair<int, xmppd::jabberid>(1, resend_jid));
			weight_sum++;
		    }
		} catch (std::invalid_argument) {
		}
	    }

	    // still no valid resend_hosts?
	    if (resend_hosts.empty()) {
		throw std::invalid_argument("resend config contains no valid destination");
	    }
	}

	bool resend_service::is_explicit_service() const {
	    return service.length() > 0;
	}

	Glib::ustring const& resend_service::get_service_prefix() const {
	    return service;
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
		    log_warn(dp->host, "Looping DNS request. Dropped: %s", xmlnode_serialize_string(dp->x, xmppd::ns_decl_list(), 0));
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
	    pending_jobs[dp->host] = new resolver_job(*this, dp);
	    return r_DONE;
	}

	resolver_job::resolver_job(resolver& owner, dpacket dp) : owner(owner) {
	    // sanity check
	    if (!dp->host) {
		throw std::invalid_argument("dpacket has no host");
	    }

	    // keep the packet
	    add_packet(dp);

	    // keep destination explicitly for faster access
	    destination = dp->host;

	    // get the services and resend destinations that we have to use (make copy)
	    resend_services = owner.get_resend_services();

	    // set current service
	    current_service = resend_services.begin();

	    // start resolving this service
	    start_resolving_service();
	}

	resolver_job::~resolver_job() {
	    // disconnect all signals pointing to us
	    for (std::list<sigc::connection>::iterator p = connected_signals.begin(); p != connected_signals.end(); ++p) {
		p->disconnect();
	    }
	}

	void resolver_job::add_packet(dpacket dp) {
	    waiting_packets.push_back(dp);
	}

	void resolver_job::start_resolving_service() {
	    // reset the list of providing hosts
	    providing_hosts.erase(providing_hosts.begin(), providing_hosts.end());

	    // do we have a service, or do have have do plain AAAA+A queries?
	    if (current_service->is_explicit_service()) {
		// need to do SRV lookup
		//
		// create query
		std::ostringstream name_to_resolve;
		name_to_resolve << std::string(current_service->get_service_prefix()) << "." << std::string(destination);

		xmppd::lwresc::rrsetbyname query(name_to_resolve.str(), ns_c_in, ns_t_srv);

		// register result callback
		connected_signals.push_back(owner.register_result_callback(query.getSerial(), sigc::mem_fun(*this, &xmppd::resolver::resolver_job::on_srv_query_result)));

		// send query
		owner.send_query(query);

		// XXX implementation needed
	    } else {
		// no SRV lookup, just plain AAAA+A

		// the hosts providing the service is just the destination on port 5269
		// so put this in providing_hosts list
		providing_hosts.push_back(std::pair<Glib::ustring, Glib::ustring>(destination, "5269"));

		// no real SRV lookup step needed, so directly start the AAAA+A query stap
		resolve_providing_hosts();
	    }
	}

	void resolver_job::resolve_providing_hosts() {
	    // XXX implement this method
	}

	void resolver_job::on_srv_query_result(xmppd::lwresc::lwresult const& result) {
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
    xmppd::resolver::resolver* ri = new xmppd::resolver::resolver(i, x);
}
