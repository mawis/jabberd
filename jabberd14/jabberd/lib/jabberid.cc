/*
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
 * @file jabberid.cc
 * @brief representation, normalization and comparison of JabberIDs (addresses
 * in XMPP)
 */

#include <jabberdlib.h>
#include <stringprep.h>

namespace xmppd {
/**
 * The preparation_cache class caches string prep results and is used to speed
 * up preparation of jabberid address parts
 *
 * The parent class xhash uses the original string as keys and the value is a
 * pair of the prepared string (empty string if prepared string equals the
 * original string) and the the time when the cache entry has been last used.
 */
class preparation_cache : private xhash<std::pair<Glib::ustring, time_t>> {
  public:
    /**
     * create a new string prep cache instance
     *
     * @param profile the stringprep profile to use (stringprep_xmpp_nodeprep,
     * stringprep_nameprep, or stringprep_xmpp_resourceprep)
     */
    preparation_cache(const ::Stringprep_profile *profile);

    /**
     * get the prepared version of the original string
     *
     * @param original the string to prepare
     * @returns the prepared string
     * @throws std::invalid_argument if the string cannot be prepared
     */
    Glib::ustring get_prepped(const Glib::ustring &original);

    /**
     * clean the preparation cache
     */
    void clean_cache();

    /**
     * prepare a node
     *
     * @param original the string to prepare as a node
     * @returns the prepared string
     * @throws std::invalid_argument if node cannot be prepared
     */
    static Glib::ustring prepare_node(const Glib::ustring &original);

    /**
     * prepare a domain
     *
     * @param original the string to prepare as a domain
     * @returns the prepared string
     * @throws std::invalid_argument if domain cannot be prepared
     */
    static Glib::ustring prepare_domain(const Glib::ustring &original);

    /**
     * prepare a resource
     *
     * @param original the string to prepare as a resource
     * @return the prepared string
     * @throws std::invalid_argument if the resource cannot be prepared
     */
    static Glib::ustring prepare_resource(const Glib::ustring &original);

  private:
    /**
     * The string prep profile to use for this cache
     */
    const ::Stringprep_profile *profile;

    /**
     * Last time the preparation cache has been cleaned
     */
    time_t last_clean;

    /**
     * preparation cache for nodes
     */
    static preparation_cache node_cache;

    /**
     * preparation cache for domains
     */
    static preparation_cache domain_cache;

    /**
     * preparation cache for resources
     */
    static preparation_cache resource_cache;
};

preparation_cache preparation_cache::node_cache(stringprep_xmpp_nodeprep);
preparation_cache preparation_cache::domain_cache(stringprep_nameprep);
preparation_cache
    preparation_cache::resource_cache(stringprep_xmpp_resourceprep);

Glib::ustring preparation_cache::prepare_node(const Glib::ustring &original) {
    return node_cache.get_prepped(original);
}

Glib::ustring preparation_cache::prepare_domain(const Glib::ustring &original) {
    return domain_cache.get_prepped(original);
}

Glib::ustring
preparation_cache::prepare_resource(const Glib::ustring &original) {
    return resource_cache.get_prepped(original);
}

preparation_cache::preparation_cache(const ::Stringprep_profile *profile)
    : profile(profile) {
    if (profile == NULL) {
        throw std::invalid_argument(
            "No profile given when constructing preparation_cache");
    }

    last_clean = std::time(NULL);
}

void preparation_cache::clean_cache() {
    time_t now = std::time(NULL);

    // cleaning already necessary?
    if (now - last_clean < 60)
        return; // no, clean at most once a minute

    // what to clean
    time_t keep_newer_as = now - 900;

    // walk cache
    std::list<Glib::ustring> items_to_remove;
    for (preparation_cache::const_iterator p = this->begin(); p != this->end();
         ++p) {
        if (p->second.second < keep_newer_as)
            items_to_remove.push_back(p->first);
    }
    for (std::list<Glib::ustring>::const_iterator p = items_to_remove.begin();
         p != items_to_remove.end(); ++p) {
        this->erase(*p);
    }
}

Glib::ustring preparation_cache::get_prepped(const Glib::ustring &original) {
    // need cleaning the cache?
    clean_cache();

    // already in cache?
    xhash<std::pair<Glib::ustring, time_t>>::iterator iter = find(original);
    if (iter != end()) {
        iter->second.second = std::time(NULL);

        if (iter->first.length() == 0) {
            return original;
        } else {
            return iter->second.first;
        }
    }

    // not yet in cache, do prepare

    // check length
    if (std::string(original).length() > 1023) {
        throw std::invalid_argument("JabberID part is to big");
    }
    // copy original to a buffer where the preparation can be executed on
    char in_out_buffer[1024];
    std::strncpy(in_out_buffer, original.c_str(), sizeof(in_out_buffer) - 1);
    in_out_buffer[sizeof(in_out_buffer) - 1] = 0; // sanity termination

    // do preparation
    int result = ::stringprep(in_out_buffer, sizeof(in_out_buffer),
                              STRINGPREP_NO_UNASSIGNED, profile);

    // success?
    if (result != ::STRINGPREP_OK) {
        throw std::invalid_argument("JabberID part cannot be prepared");
    }

    // cache entry
    operator[](original) =
        std::pair<Glib::ustring, time_t>(in_out_buffer, std::time(NULL));

    // return result
    return in_out_buffer;
}

jabberid::jabberid(const Glib::ustring &jid) {
    // split the JID into parts
    Glib::ustring::size_type resource_separator = jid.find("/");
    Glib::ustring::size_type node_separator = jid.find("@");

    // there might be no node, but an at sign in the resource
    if (resource_separator != Glib::ustring::npos &&
        node_separator != Glib::ustring::npos &&
        node_separator > resource_separator) {
        node_separator = Glib::ustring::npos;
    }

    // prepare and store the parts
    set_domain(jid.substr(
        node_separator == Glib::ustring::npos ? 0 : node_separator + 1,
        node_separator == Glib::ustring::npos
            ? resource_separator
            : resource_separator == Glib::ustring::npos
                  ? Glib::ustring::npos
                  : resource_separator - node_separator - 1));
    if (node_separator != Glib::ustring::npos) {
        set_node(jid.substr(0, node_separator));
    }
    if (resource_separator != Glib::ustring::npos) {
        set_resource(jid.substr(resource_separator + 1));
    }
}

void jabberid::set_node(const Glib::ustring &node) {
    // clearing node?
    if (node.size() == 0) {
        this->node = "";
        return;
    }

    try {
        this->node = preparation_cache::prepare_node(node);
    } catch (std::invalid_argument) {
        throw std::invalid_argument("Invalid node for JID");
    }
}

void jabberid::set_domain(const Glib::ustring &domain) {
    try {
        this->domain = preparation_cache::prepare_domain(domain);
    } catch (std::invalid_argument) {
        throw std::invalid_argument("Invalid domain for JID");
    }
}

void jabberid::set_resource(const Glib::ustring &resource) {
    // clearing resource?
    if (resource.size() == 0) {
        this->resource = "";
        return;
    }

    try {
        this->resource = preparation_cache::prepare_resource(resource);
    } catch (std::invalid_argument) {
        throw std::invalid_argument("Invalid resource for JID");
    }
}

bool jabberid::operator==(const jabberid &otherjid) {
    return compare(otherjid, true, true, true);
}

bool jabberid::compare(const jabberid &otherjid, bool compare_resource,
                       bool compare_node, bool compare_domain) {
    if (compare_domain && domain != otherjid.domain)
        return false;
    if (compare_node && node != otherjid.node)
        return false;
    if (compare_resource && resource != otherjid.resource)
        return false;
    return true;
}

jabberid jabberid::get_user() {
    jabberid jabberid_copy(*this);
    jabberid_copy.set_resource("");
    return jabberid_copy;
}

Glib::ustring jabberid::full() {
    std::ostringstream result;
    if (node.size() > 0) {
        result << std::string(node) << "@";
    }
    result << std::string(domain);
    if (resource.size() > 0) {
        result << "/" << std::string(resource);
    }

    return result.str();
}

jabberid_pool::jabberid_pool(const Glib::ustring &jid, ::pool p)
    : jabberid(jid), next(NULL), jid_full(NULL) {
    if (p == NULL) {
        throw std::invalid_argument(
            "trying to construct jabberid_pool with a NULL pool");
    }

    this->p = p;
}

void jabberid_pool::set_node(const Glib::ustring &node) {
    jid_full = NULL;
    jabberid::set_node(node);
}

void jabberid_pool::set_domain(const Glib::ustring &domain) {
    jid_full = NULL;
    jabberid::set_domain(domain);
}

void jabberid_pool::set_resource(const Glib::ustring &resource) {
    jid_full = NULL;
    jabberid::set_resource(resource);
}

char *jabberid_pool::full_pooled() {
    if (!jid_full) {
        jid_full = pstrdup(p, full().c_str());
    }

    return jid_full;
}
} // namespace xmppd
