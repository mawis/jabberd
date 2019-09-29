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

#include <resolver.h>

#include <namespaces.hh>

namespace xmppd {
namespace resolver {
resend_service::resend_service(xmlnode resend) : weight_sum(0) {
    char const *service_attribute_value =
        xmlnode_get_attrib_ns(resend, "service", NULL);

    // if there is a service attribute, keep it
    if (service_attribute_value)
        service = service_attribute_value;

    // check, get and iterate partial childs
    xht namespaces = xhash_new(3);
    xhash_put(namespaces, "dnsrv", const_cast<char *>(NS_JABBERD_CONFIG_DNSRV));
    xmlnode_vector partial_elements =
        xmlnode_get_tags(resend, "dnsrv:partial", namespaces);
    xhash_free(namespaces);
    namespaces = NULL;
    for (xmlnode_vector::iterator p = partial_elements.begin();
         p != partial_elements.end(); ++p) {
        // get the weight for this partial destination
        char const *weight_attrib = xmlnode_get_attrib_ns(*p, "weight", NULL);
        int weight = 1;
        if (weight_attrib) {
            std::istringstream weight_stream(weight_attrib);
            weight_stream >> weight;
        }
        if (weight < 1)
            weight = 1;

        // get the destination
        char const *resend_dest = xmlnode_get_data(*p);
        if (!resend_dest)
            continue;
        try {
            xmppd::jabberid resend_jid(resend_dest);

            // keep
            resend_hosts.push_back(
                std::pair<int, xmppd::jabberid>(weight, resend_jid));
            weight_sum += weight;
        } catch (std::invalid_argument&) {
            continue;
        }
    }

    // if there where no partial childs, use the text() child of the <resend/>
    // element
    if (resend_hosts.empty()) {
        try {
            char const *resend_dest = xmlnode_get_data(resend);
            if (resend_dest) {
                xmppd::jabberid resend_jid(resend_dest);

                // keep
                resend_hosts.push_back(
                    std::pair<int, xmppd::jabberid>(1, resend_jid));
                weight_sum++;
            }
        } catch (std::invalid_argument&) {
        }
    }

    // still no valid resend_hosts?
    if (resend_hosts.empty()) {
        throw std::invalid_argument(
            "resend config contains no valid destination");
    }
}

bool resend_service::is_explicit_service() const {
    return service.length() > 0;
}

Glib::ustring const &resend_service::get_service_prefix() const {
    return service;
}

xmppd::jabberid resend_service::get_resend_host() const {
    int host_die = std::rand() % weight_sum;

    for (std::list<std::pair<int, xmppd::jabberid>>::const_iterator p =
             resend_hosts.begin();
         p != resend_hosts.end(); ++p) {
        host_die -= p->first;

        if (host_die <= 0) {
            return p->second;
        }
    }

    return resend_hosts.begin()->second;
}
} // namespace resolver
} // namespace xmppd
