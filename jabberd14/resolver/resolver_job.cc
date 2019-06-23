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
 * This is a module for xmppd that implements a resolver that resolves DNS names
 * by delegating the actual requests to a lwresd.
 */

#include <iostream>
#include <resolver.h>

namespace xmppd {
namespace resolver {
long resolver_job::next_serial = 1;

resolver_job::resolver_job(resolver &owner, dpacket dp)
    : owner(owner), serial(next_serial++) {
    // remember when this job has been generated
    std::time(&timestamp);

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
    for (std::list<sigc::connection>::iterator p = connected_signals.begin();
         p != connected_signals.end(); ++p) {
        p->disconnect();
    }
}

void resolver_job::add_packet(dpacket dp) { waiting_packets.push_back(dp); }

void resolver_job::start_resolving_service() {
    // reset the list of providing hosts
    providing_hosts.erase(providing_hosts.begin(), providing_hosts.end());

    // do we have a service, or do have have do plain AAAA+A queries?
    if (current_service->is_explicit_service()) {
        // need to do SRV lookup
        //
        // create query
        std::ostringstream name_to_resolve;
        name_to_resolve << std::string(current_service->get_service_prefix())
                        << "." << std::string(destination);

        xmppd::lwresc::rrsetbyname query(name_to_resolve.str(), ns_c_in,
                                         ns_t_srv);

        // register result callback
        connected_signals.push_back(owner.register_result_callback(
            query.getSerial(),
            sigc::mem_fun(
                *this, &xmppd::resolver::resolver_job::on_srv_query_result)));

        // send query
        owner.send_query(query);
    } else {
        // no SRV lookup, just plain AAAA+A

        // the hosts providing the service is just the destination on port 5269
        // so put this in providing_hosts list
        providing_hosts.push_back(
            std::pair<Glib::ustring, Glib::ustring>(destination, "5269"));

        // no real SRV lookup step needed, so directly start the AAAA+A query
        // stap
        resolve_providing_hosts();
    }
}

void resolver_job::on_a_query_result(xmppd::lwresc::lwresult const &result) {
    // did we successfully get a result?
    if (result.getResult() == xmppd::lwresc::lwresult::res_success) {
        // we got a result, process it
        try {
            xmppd::lwresc::lwresult_rrset const *rrSet =
                dynamic_cast<xmppd::lwresc::lwresult_rrset const *>(
                    result.getRData());
            if (rrSet == NULL) {
                return;
            }

            // get the returned records
            std::vector<xmppd::lwresc::rrecord *> rrs = rrSet->getRR();

            // iterate them to find SRV records
            for (std::vector<xmppd::lwresc::rrecord *>::const_iterator p =
                     rrs.begin();
                 p != rrs.end(); ++p) {
                try {
                    xmppd::lwresc::a_record const *rr =
                        dynamic_cast<xmppd::lwresc::a_record const *>(*p);

                    result_buffer << "," << rr->getAddress() << ":"
                                  << current_providing_host->second;
                } catch (std::bad_cast) {
                }
            }

        } catch (std::bad_cast) {
            // we expected to get a lwresult_rrset on successfull resolving of
            // our query
        }
    }

    // resolve the next providing host
    ++current_providing_host;

    // resolve the now current host
    resolve_current_providing_host();
}

void resolver_job::resolve_current_providing_host_a() {
    // create the query
    xmppd::lwresc::rrsetbyname query(current_providing_host->first, ns_c_in,
                                     ns_t_a);

    // register result callback
    connected_signals.push_back(owner.register_result_callback(
        query.getSerial(),
        sigc::mem_fun(*this,
                      &xmppd::resolver::resolver_job::on_a_query_result)));

    // send query
    owner.send_query(query);
}

void resolver_job::on_aaaa_query_result(xmppd::lwresc::lwresult const &result) {
    // did we successfully get a result?
    if (result.getResult() == xmppd::lwresc::lwresult::res_success) {
        // we got a result, process it
        try {
            xmppd::lwresc::lwresult_rrset const *rrSet =
                dynamic_cast<xmppd::lwresc::lwresult_rrset const *>(
                    result.getRData());
            if (rrSet == NULL) {
                return;
            }

            // get the returned records
            std::vector<xmppd::lwresc::rrecord *> rrs = rrSet->getRR();

            // iterate them to find SRV records
            for (std::vector<xmppd::lwresc::rrecord *>::const_iterator p =
                     rrs.begin();
                 p != rrs.end(); ++p) {
                try {
                    xmppd::lwresc::aaaa_record const *rr =
                        dynamic_cast<xmppd::lwresc::aaaa_record const *>(*p);

                    result_buffer << ",[" << rr->getAddress()
                                  << "]:" << current_providing_host->second;
                } catch (std::bad_cast) {
                }
            }

        } catch (std::bad_cast) {
            // we expected to get a lwresult_rrset on successfull resolving of
            // our query
        }
    }

    // try A lookup
    resolve_current_providing_host_a();
    return;
}

void resolver_job::resolve_current_providing_host() {
    if (current_providing_host == providing_hosts.end()) {
        // we resolved everything, notify listener
        for (std::list<sigc::signal<void, resolver_job &>>::iterator p =
                 result_listeners.begin();
             p != result_listeners.end(); ++p) {
            p->emit(*this);
        }
        return;
    }

    // create the query
    xmppd::lwresc::rrsetbyname query(current_providing_host->first, ns_c_in,
                                     ns_t_aaaa);

    // register result callback
    connected_signals.push_back(owner.register_result_callback(
        query.getSerial(),
        sigc::mem_fun(*this,
                      &xmppd::resolver::resolver_job::on_aaaa_query_result)));

    // send query
    owner.send_query(query);
}

void resolver_job::resolve_providing_hosts() {
    // make the first one the current
    current_providing_host = providing_hosts.begin();

    // resolve the now current host
    resolve_current_providing_host();
}

void resolver_job::on_srv_query_result(xmppd::lwresc::lwresult const &result) {
    // did we successfully get a result?
    if (result.getResult() != xmppd::lwresc::lwresult::res_success) {
        // try next service
        ++current_service;
        start_resolving_service();
        return;
    }

    // we got a result, process it
    try {
        xmppd::lwresc::lwresult_rrset const *rrSet =
            dynamic_cast<xmppd::lwresc::lwresult_rrset const *>(
                result.getRData());
        if (rrSet == NULL) {
            return;
        }

        // get the returned records
        std::vector<xmppd::lwresc::rrecord *> rrs = rrSet->getRR();

        // iterate them to find SRV records
        bool found_srv_record = false;
        for (std::vector<xmppd::lwresc::rrecord *>::const_iterator p =
                 rrs.begin();
             p != rrs.end(); ++p) {
            try {
                xmppd::lwresc::srv_record const *rr =
                    dynamic_cast<xmppd::lwresc::srv_record const *>(*p);
                found_srv_record = true;

                // XXX the following line is only for debugging
                std::cout << "One SRV result for " << destination << "/"
                          << current_service->get_service_prefix()
                          << " is: " << rr->getPrio() << " " << rr->getWeight()
                          << " " << rr->getDName() << ":" << rr->getPort()
                          << std::endl;

                // XXX we have to sort by priority and weight

                // for now, add unsorted to the list
                std::ostringstream port;
                port << rr->getPort();
                providing_hosts.push_back(
                    std::pair<Glib::ustring, Glib::ustring>(rr->getDName(),
                                                            port.str()));

            } catch (std::bad_cast) {
                // it hasn't been a SRV record - we can ignore it
            }
        }

        // if we found something we have to resolve the providing hosts, else
        // try next service
        if (found_srv_record) {
            // resolve the returned locations to IP addresses
            resolve_providing_hosts();
        } else {
            // try next service
            ++current_service;
            start_resolving_service();
        }

    } catch (std::bad_cast) {
        // we expected to get a lwresult_rrset on successfull resolving of our
        // query
    }
}

sigc::connection resolver_job::register_result_callback(
    sigc::signal<void, resolver_job &>::slot_type const &callback) {
    sigc::signal<void, resolver_job &> new_signal =
        sigc::signal<void, resolver_job &>();
    sigc::connection result = new_signal.connect(callback);
    result_listeners.push_back(new_signal);
    return result;
}

Glib::ustring resolver_job::get_result() const {
    std::string result = result_buffer.str();
    if (result.length() < 1)
        return result;
    return result.substr(1);
}

std::list<dpacket> const &resolver_job::get_packets() const {
    return waiting_packets;
}

xmppd::jabberid resolver_job::get_resend_host() const {
    return current_service->get_resend_host();
}

std::ostream &operator<<(std::ostream &out, resolver_job &job) {
    time_t now = std::time(NULL);
    out << "JOB#" << job.serial << "(" << (now - job.timestamp) << " s): ";
    out << job.destination << " " << job.get_result();
    return out;
}
} // namespace resolver
} // namespace xmppd
