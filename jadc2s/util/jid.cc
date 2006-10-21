/*
 * Licence
 *
 * Copyright (c) 2006 Matthias Wimmer,
 *                    mailto:m@tthias.eu, xmpp:mawis@amessage.info
 *
 * You can use the content of this file using one of the following licences:
 *
 * - Version 1.0 of the Jabber Open Source Licence ("JOSL")
 * - GNU GENERAL PUBLIC LICENSE, Version 2 or any newer version of this licence at your choice
 * - Apache Licence, Version 2.0
 * - GNU Lesser General Public License, Version 2.1 or any newer version of this licence at your choice
 * - Mozilla Public License 1.1
 */

/**
 * @file jid.cc
 * @brief Handling of JabberIDs
 *
 * This file contains functions to store, manipulate, and compare JabberIDs
 */

#include "util.h"

#include <sstream>
#include <cstring>

namespace xmppd {
    stringprep_cache::stringprep_cache(const ::Stringprep_profile *profile) : profile(profile) {
	if (profile == NULL)
	    throw Glib::ustring("No profile specified when creating an xmppd::stringprep_cache");
    }

    void stringprep_cache::clean_cache(std::time_t seconds) {
	// calculate the timestamp an entry has to have at least to be kept
	std::time_t keep_newer_as = std::time(NULL) - seconds;

	// check all entries and keep old ones
	std::map<Glib::ustring, stringprep_cache_entry>::iterator p;
	for (p=hashtable.begin(); p!=hashtable.end(); ++p) {
	    if (p->second.last_used < keep_newer_as)
		hashtable.erase(p);
	}
    }

    int stringprep_cache::stringprep(Glib::ustring &in_out_string) {
	// is there something we have to stringprep?
	if (in_out_string == "")
	    return STRINGPREP_OK;

	// check if the requested preparation has already been done
	std::map<Glib::ustring, stringprep_cache_entry>::iterator p = hashtable.find(in_out_string);
	if (p != hashtable.end()) {
	    // found cached entry

	    // update the statistics
	    p->second.used_count++;
	    p->second.last_used = std::time(NULL);

	    // something needs to be changed?
	    if (p->second.preped != "")
		in_out_string = p->second.preped;

	    // we have finished with this
	    return STRINGPREP_OK;
	}

	// no cached entry, we have to stringprep
	
	// check the length of the string to prep - using bytes instead of characters
	if (std::string(in_out_string).length() > 1023)
	    return STRINGPREP_TOO_SMALL_BUFFER;

	// we need a C string to call stringprep
	char in_out_buffer[1024];
	std::strcpy(in_out_buffer, in_out_string.c_str());

	// do the hard work
	int result = ::stringprep(in_out_buffer, sizeof(in_out_buffer), STRINGPREP_NO_UNASSIGNED, profile);

	// if we could stringprep, copy the result back to the C++ string, and cache the entry
	if (result == STRINGPREP_OK) {
	    // create cache entry
	    struct stringprep_cache_entry cache_entry;
	    cache_entry.last_used = std::time(NULL);
	    cache_entry.used_count = 1;
	    if (in_out_string != in_out_buffer) {
		cache_entry.preped = in_out_buffer;
	    }
	    hashtable[in_out_string] = cache_entry;

	    // copy the result back
	    in_out_string = in_out_buffer;
	}

	// return the stringprep result code
	return result;
    }

    jid_environment::jid_environment() :
	nodes(new stringprep_cache(::stringprep_xmpp_nodeprep)),
	domains(new stringprep_cache(::stringprep_nameprep)),
	resources(new stringprep_cache(::stringprep_xmpp_resourceprep)) {
    }

    jid::jid(jid_environment environment, Glib::ustring address_string) : environment(environment) {
	// find resource
	Glib::ustring::size_type slash_pos = address_string.find('/');

	if (slash_pos != Glib::ustring::npos) {
	    set_resource(address_string.substr(slash_pos+1));
	    address_string.erase(slash_pos);
	}

	// find node
	Glib::ustring::size_type at_pos = address_string.find('@');

	if (at_pos != Glib::ustring::npos) {
	    set_node(address_string.substr(0, at_pos));
	    address_string.erase(0, at_pos+1);
	}

	// remainder is the domain
	set_domain(address_string);
    }

    bool jid::operator==(const jid &other_jid) {
	return (node == other_jid.node) && (domain == other_jid.domain) && (resource == other_jid.resource);
    }

    bool jid::cmpx(const jid &other_jid, bool cmp_node, bool cmp_resource, bool cmp_domain) {
	return (!cmp_node || node == other_jid.node) && (!cmp_domain || domain == other_jid.domain) && (!cmp_resource || resource == other_jid.resource);
    }

    void jid::set_node(Glib::ustring new_node) {
	if (environment.nodes->stringprep(new_node) == STRINGPREP_OK) {
	    full_cache = "";
	    node = new_node;
	}
    }

    void jid::set_domain(Glib::ustring new_domain) {
	if (environment.domains->stringprep(new_domain) == STRINGPREP_OK) {
	    // XXX do punicode decode
	    full_cache = "";
	    domain = new_domain;
	}
    }

    void jid::set_resource(Glib::ustring new_resource) {
	if (environment.resources->stringprep(new_resource) == STRINGPREP_OK) {
	    full_cache = "";
	    resource = new_resource;
	}
    }

    const Glib::ustring& jid::full() const {
	// (re)create result?
	if (full_cache == "") {
	    std::ostringstream result;

	    if (node != "")
		result << node << "@";
	    result << domain;
	    if (resource != "")
		result << "/" << resource;

	    full_cache = result.str();
	}

	return full_cache;
    }

    std::ostringstream &operator<<(std::ostringstream &stream, const jid address) {
	stream << address.full();
	return stream;
    }

    const Glib::ustring& jid::get_node() {
	return node;
    }

    const Glib::ustring& jid::get_domain() {
	return domain;
    }

    const Glib::ustring& jid::get_resource() {
	return resource;
    }

    bool jid::has_node() {
	return node != "";
    }

    bool jid::has_domain() {
	return domain != "";
    }

    bool jid::has_resource() {
	return resource != "";
    }
}
