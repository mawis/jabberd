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
 * @file config.cc
 * @brief access to configuration values
 *
 * This file implements the access to configuration settings, currently implemented based on reading an XML file.
 */

#include "util.h"

namespace xmppd {

    configuration::configuration(const Glib::ustring& configfile) : xmlpp::SaxParser() {
	// Parse the configuration file
	try {
	    set_substitute_entities(true);
	    parse_file(configfile);
	} catch (const xmlpp::exception& ex) {
	    throw Glib::ustring(ex.what());
	}
    }

    configuration::~configuration() {
    }

    void configuration::on_end_element(const Glib::ustring& name) {
	configuration_entry new_entry;
	new_entry.value = parse_buffer;
	parse_buffer = "";

	operator[](path_stack.top()).push_back(new_entry);

	path_stack.pop();
    }

    void configuration::on_start_element(const Glib::ustring& name, const AttributeList& attributes) {
	// push new path to a possible value to the path_stack
	Glib::ustring new_path;
	if (!path_stack.empty()) {
	    if (path_stack.top() == "") {
		new_path = name;
	    } else {
		new_path = path_stack.top() + "." + name;
	    }
	}

	path_stack.push(new_path);

	parse_buffer = "";
    }

    void configuration::on_characters(const Glib::ustring& text) {
	parse_buffer += text;
    }

    const Glib::ustring& configuration::get_string(const Glib::ustring& what) {
	if (find(what) == end())
	    throw Glib::ustring("Request for unset configuration setting: ")+what;

	if (operator[](what).empty())
	    throw Glib::ustring("Internal error: empty list in configuration instance.");

	return operator[](what).front().value;
    }

    int configuration::get_integer(const Glib::ustring& what) {
	std::istringstream result_stream(get_string(what));
	int result = 0;
	result_stream >> result;
	return result;
    }
}
