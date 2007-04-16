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
 * @file proxy65.cc
 * @brief This implements a proxy component for XEP-0065 bytestreams
 *
 * This is a module for jabberd14 that implements a proxy for XEP-0065 bytestreams.
 */

#include <proxy65.h>
#include <stdexcept>
#include <ctime>
#include <vector>

namespace xmppd {
    namespace proxy65 {
	proxy65::proxy65(instance i, xmlnode x) : instance_base(i, x) {
	    // allocate our standard namespace prefixes
	    std_namespace_prefixes = xhash_new(3);
	    xhash_put(std_namespace_prefixes, "", const_cast<char*>(NS_SERVER));
	    xhash_put(std_namespace_prefixes, "bytestreams", const_cast<char*>(NS_BYTESTREAMS));

	    // open the socket to listen on
	    // XXX IP and port needs to be configurable, fixed for now
	    mio m = mio_listen(6565, "::", proxy65::conn_accepted_wrapper, this, MIO_LISTEN_RAW);
	}

	void proxy65::conn_accepted_wrapper(mio m, int state, void *arg, xmlnode unused1, char* unused2, int unused3) {
	    // sanity checks
	    if (m == NULL || state != MIO_NEW || arg == NULL)
		return;

	    static_cast<proxy65*>(arg)->connection_accepted(m);
	}

	void proxy65::connection_accepted(mio m) {
	    // create new stub for this connection
	    socks5stub* stub = new socks5stub(m);

	    // connect signals
	    stub->event_disconnected().connect(sigc::mem_fun(*this, &proxy65::connecting_connection_disconnected));
	    stub->event_protocol_done().connect(sigc::mem_fun(*this, &proxy65::connecting_connection_protocol_done));

	    // put the connection in the map of connecting connections
	    connecting_connections[stub] = std::time(NULL);
	}

	void proxy65::connecting_connection_disconnected(socks5stub* stub) {
	    connecting_connections.erase(stub);
	    disconnected_connections.insert(stub);
	}

	void proxy65::connecting_connection_protocol_done(socks5stub* stub) {
	    connecting_connections.erase(stub);

	    waiting_connections.insert(std::pair<std::string, std::pair<socks5stub*, time_t> >(stub->get_connection_id(), std::pair<socks5stub*, time_t>(stub, std::time(NULL))));
	}

	result proxy65::on_iq_stanza(jpacket p) {
	    // get the namespace of the iq content
	    std::string iq_type;
	    try {
		iq_type = xmlnode_get_namespace(p->iq);
	    } catch (std::exception) {
		// probably we did not get any content in the iq stanza
		bounce_stanza(p->x, XTERROR_BAD);
		return r_DONE;
	    }

	    // is it a disco#info request?
	    if (iq_type == NS_DISCO_INFO)
		return iq_disco_info(p);

	    // is it a disco#items request?
	    if (iq_type == NS_DISCO_ITEMS)
		return iq_disco_items(p);

	    // is it a network address discovery?
	    if (iq_type == NS_BYTESTREAMS)
		return iq_bytestreams(p);

	    // if the stanza is not yet handled, we do not support it
	    bounce_stanza(p->x, XTERROR_NOTIMPL);
	    return r_DONE;
	}

	result proxy65::iq_disco_info(jpacket p) {
	    xmlnode x=NULL;

	    switch (jpacket_subtype(p)) {
		case JPACKET__GET:
		    jutil_iqresult(p->x);
		    p->iq = xmlnode_insert_tag_ns(p->x, "query", NULL, NS_DISCO_INFO);
		    x = xmlnode_insert_tag_ns(p->iq, "identity", NULL, NS_DISCO_INFO);
		    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "proxy");
		    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "bytestreams");
		    xmlnode_put_attrib_ns(x, "name", NULL, NULL, "File transfer helper");
		    x = xmlnode_insert_tag_ns(p->iq, "feature", NULL, NS_DISCO_INFO);
		    xmlnode_put_attrib_ns(x, "var", NULL, NULL, NS_BYTESTREAMS);
		    deliver(p->x);
		    return r_DONE;
		case JPACKET__SET:
		    bounce_stanza(p->x, XTERROR_FORBIDDEN);
		    return r_DONE;
		default:
		    xmlnode_free(p->x);
		    return r_DONE;
	    }
	}

	result proxy65::iq_disco_items(jpacket p) {
	    switch (jpacket_subtype(p)) {
		case JPACKET__GET:
		    jutil_iqresult(p->x);
		    p->iq = xmlnode_insert_tag_ns(p->x, "query", NULL, NS_DISCO_ITEMS);
		    deliver(p->x);
		    return r_DONE;
		case JPACKET__SET:
		    bounce_stanza(p->x, XTERROR_FORBIDDEN);
		    return r_DONE;
		default:
		    xmlnode_free(p->x);
		    return r_DONE;
	    }
	}

	result proxy65::iq_bytestreams(jpacket p) {
	    xmlnode x = NULL;

	    switch (jpacket_subtype(p)) {
		case JPACKET__GET:
		    jutil_iqresult(p->x);
		    p->iq = xmlnode_insert_tag_ns(p->x, "query", NULL, NS_BYTESTREAMS);
		    x = xmlnode_insert_tag_ns(p->iq, "streamhost", NULL, NS_BYTESTREAMS);
		    xmlnode_put_attrib_ns(x, "jid", NULL, NULL, get_instance_id().c_str());
		    xmlnode_put_attrib_ns(x, "host", NULL, NULL, get_instance_id().c_str());
		    xmlnode_put_attrib_ns(x, "port", NULL, NULL, "6565");	// XXX should get configured
		    deliver(p->x);
		    return r_DONE;
		case JPACKET__SET:
		    return iq_bytestreams_activate(p);
		default:
		    xmlnode_free(p->x);
		    return r_DONE;
	    }
	}

	result proxy65::iq_bytestreams_activate(jpacket p) {
	    // get who initiated the connection
	    char const* initiator = jid_full(p->from);

	    // get the session id
	    char const* sid = xmlnode_get_attrib_ns(p->iq, "sid", NULL);
	    if (!sid) {
		bounce_stanza(p->x, XTERROR_BAD);
		return r_DONE;
	    }

	    // get the target of the connection
	    xmlnode_list_item activate = xmlnode_get_tags(p->iq, "bytestreams:activate", std_namespace_prefixes);
	    if (!activate) {
		bounce_stanza(p->x, XTERROR_BAD);
		return r_DONE;
	    }
	    char const* target = jid_full(jid_new(p->p, xmlnode_get_data(activate->node)));
	    if (!target) {
		bounce_stanza(p->x, XTERROR_BAD);
		return r_DONE;
	    }

	    // calculate the hash of the connection
	    xmppd::sha1 session_hash;
	    session_hash.update(sid);
	    session_hash.update(initiator);
	    session_hash.update(target);
	    std::string session_id = session_hash.final_hex();

	    // check if we have two waiting connections with this session_id
	    std::vector<socks5stub*> matched_connections;
	    std::multimap<std::string, std::pair<socks5stub*, time_t> >::iterator iter;
	    for (iter = waiting_connections.begin(); iter != waiting_connections.end(); ++iter) {
		if (iter->first == session_id) {
		    matched_connections.push_back(iter->second.first);
		    waiting_connections.erase(iter);
		}
	    }

	    // we should have found exactly two connections
	    if (matched_connections.size() != 2) {
		std::vector<socks5stub*>::iterator iter;
		for (iter = matched_connections.begin(); iter != matched_connections.end(); ++iter) {
		    // XXX signal failure to the connection
		    disconnected_connections.insert(*iter);	// XXX take care that we do not double delete instance after we signal failure above
		}

		// signal failure
		bounce_stanza(p->x, XTERROR_NOTALLOWED);
		return r_DONE;
	    }

	    // interconnect the two connections
	    connected_sockets* new_conn = new connected_sockets(matched_connections[1], matched_connections[2]);
	    new_conn->event_closed().connect(sigc::mem_fun(*this, &proxy65::active_connection_disconnected));
	    active_connections.insert(new_conn);		// XXX protect this for the case that it diconnectes before it gets inserted
	    
	    // send result
	    jutil_iqresult(p->x);
	    deliver(p->x);
	    return r_DONE;
	}

	void proxy65::active_connection_disconnected(connected_sockets* conn) {
	    active_connections.erase(conn);
	}

	socks5stub::socks5stub(mio m) : m(m), current_state(state_connected) {
	    mio_reset(m, socks5stub::mio_event_wrapper, this);
	}

	void socks5stub::mio_event_wrapper(mio m, int state, void *arg, xmlnode unused1, char* buffer, int bufferlen) {
	    // sanity check
	    if (arg == NULL)
		return;

	    // call handler on instance based on event state
	    switch (state) {
		case MIO_CLOSED:
		    static_cast<socks5stub*>(arg)->on_closed();
		    break;
		case MIO_BUFFER:
		    if (bufferlen > 0 && buffer != NULL)
			static_cast<socks5stub*>(arg)->on_data(std::string(buffer, bufferlen));
		    break;
	    }
	}

	void socks5stub::on_data(const std::string& received_data) {
	    unprocessed_data += received_data;

	    // what we do depends on our current state
	    switch (current_state) {
		case state_connected:
		    // if no data yet available, we cannot process anything (should not happen as we just received data)
		    if (unprocessed_data.length() < 1)
			return;

		    // check the version the client proposed (we only support version 5)
		    if (unprocessed_data[0] != 5) {
			mio_write(m, NULL, "\x05\xFF", 2);
			mio_close(m);
			unprocessed_data = "";
			current_state = state_error;
			return;
		    }

		    // more than just the version received?
		    if (unprocessed_data.length() < 2)
			return;

		    // already full version identifier received?
		    if (unprocessed_data.length() >= 2 + unprocessed_data[1]) {
			// yes we received version and all methods the client proposes
			
			// check if client supports 'no authentication'
			if (unprocessed_data.substr(2, unprocessed_data[1]).find(static_cast<char>(0)) != std::string::npos) {
			    // 'no auth' supported by client
			    mio_write(m, NULL, "\x05\x00", 2);
			    current_state = state_accepted_auth;
			    unprocessed_data.erase(0, 2 + unprocessed_data[1]);

			    // if data is left, try processing this data now
			    if (unprocessed_data.length() > 0)
				on_data("");
			    return;
			}

			mio_write(m, NULL, "\x05\xFF", 2);
			mio_close(m);
			current_state = state_error;
			unprocessed_data = "";
			return;
		    }

		    // still waiting for more data
		    return;
		case state_accepted_auth:
		    // check if we already have a version to check
		    if (unprocessed_data.length() < 1)
			return;

		    // check version
		    if (unprocessed_data[0] != 5) {
			mio_write(m, NULL, "\x05\x07\0x00\x01\x00\x00\x00\x00\x00\x00", 10);
			mio_close(m);
			current_state = state_error;
			unprocessed_data = "";
			return;
		    }

		    // command already available?
		    if (unprocessed_data.length() < 2)
			return;

		    // check command
		    if (unprocessed_data[1] != 1) {
			mio_write(m, NULL, "\x05\x07\0x00\x01\x00\x00\x00\x00\x00\x00", 10);
			mio_close(m);
			current_state = state_error;
			unprocessed_data = "";
			return;
		    }

		    // we do not check the content of the reserved byte

		    // address type already available?
		    if (unprocessed_data.length() < 4)
			return;

		    // check address type
		    if (unprocessed_data[3] != 3) {
			mio_write(m, NULL, "\x05\x07\0x00\x01\x00\x00\x00\x00\x00\x00", 10);
			mio_close(m);
			current_state = state_error;
			unprocessed_data = "";
			return;
		    }

		    // address length byte already available?
		    if (unprocessed_data.length() < 5)
			return;

		    // address and port already available?
		    if (unprocessed_data.length() < 7 + unprocessed_data[4])
			return;

		    // we do not check the port but consider it to be reserved
		    // I see no reason for checking it that it is set to 0.
		   
		    // get the 'address' ... well it's a sha1 hash in XEP-0065
		    connection_id = unprocessed_data.substr(5, unprocessed_data[4]);

		    // change the connection_id to lowercase
		    {
			xmppd::to_lower to_lowercase(std::locale::classic());
			std::transform(connection_id.begin(), connection_id.end(), connection_id.begin(), to_lowercase);
		    }

		    // send reply message
		    mio_write(m, NULL, (std::string("\x05\x00\x00\x03", 4)+unprocessed_data.substr(4, unprocessed_data[4]+3)).c_str(), 7+unprocessed_data[4]);
		    current_state = state_accepted_connect;
		    unprocessed_data.erase(0, 7 + unprocessed_data[4]);

		    // send signal, that we are done
		    protocol_done(this);
		    return;
		case state_accepted_connect:
		    // we are only collecting the data, the responsibility for the connection gets transfered
		    break;
		case state_error:
		    // we don't care about any data anymore
		    unprocessed_data = "";
		    break;
	    }
	}

	void socks5stub::on_closed() {
	    // send signal
	    disconnected(this);
	}

	connected_sockets::connected_sockets(socks5stub* socket1, socks5stub* socket2) {
	    // sanity checks
	    if (!socket1 || !socket2)
		throw std::invalid_argument("NULL socket passed to connected_sockets constructor");
	    if (!socket1->m || !socket2->m)
		throw std::invalid_argument("socks5stub passed to connected_sockets constructor, that has no connection");

	    // take over the connections
	    this->sockets[0] = socket1->m;
	    socket1->m = NULL;
	    this->sockets[1] = socket2->m;
	    socket2->m = NULL;

	    // register new event handlers
	    mio_reset(this->sockets[0], connected_sockets::mio_event_wrapper, this);
	    mio_reset(this->sockets[1], connected_sockets::mio_event_wrapper, this);

	    // forward data, that has been already received and buffered
	    if (socket1->unprocessed_data.length() > 0) {
		mio_write(this->sockets[1], NULL, socket1->unprocessed_data.c_str(), socket1->unprocessed_data.length());
		socket1->unprocessed_data = "";
	    }
	    if (socket2->unprocessed_data.length() > 0) {
		mio_write(this->sockets[0], NULL, socket2->unprocessed_data.c_str(), socket2->unprocessed_data.length());
		socket2->unprocessed_data = "";
	    }
	}

	void connected_sockets::mio_event_wrapper(mio m, int state, void *arg, xmlnode unused1, char* buffer, int bufferlen) {
	    // sanity check
	    if (arg == NULL || m == NULL)
		return;

	    // check for which socket this event is
	    int socketindex = 0;
	    if (m == static_cast<connected_sockets*>(arg)->sockets[1])
		socketindex = 1;

	    // call handler on instance based on event state
	    switch (state) {
		case MIO_CLOSED:
		    static_cast<connected_sockets*>(arg)->on_closed(socketindex);
		    break;
		case MIO_BUFFER:
		    if (bufferlen > 0 && buffer != NULL)
			static_cast<connected_sockets*>(arg)->on_data(socketindex, std::string(buffer, bufferlen));
		    break;
	    }
	}

	void connected_sockets::on_closed(int socketindex) {
	    int othersocket = 1 - socketindex;

	    if (sockets[othersocket]) {
		mio_close(sockets[othersocket]);
	    }

	    sockets[0] = NULL;
	    sockets[1] = NULL;
	}

	void connected_sockets::on_data(int socketindex, const std::string& received_data) {
	    int othersocket = 1 - socketindex;

	    if (sockets[othersocket]) {
		mio_write(sockets[othersocket], NULL, received_data.c_str(), received_data.length());
	    }
	}
    }
}

/**
 * init and register the proxy65 component in the server
 *
 * @todo care for destructing the proxy65 instance on shutdown
 *
 * @param i the jabber server's data about this instance
 * @param x xmlnode of this instances configuration (???)
 */
extern "C" void proxy65(instance i, xmlnode x) {
    xmppd::proxy65::proxy65* pi = new xmppd::proxy65::proxy65(i, x);
}
