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
 * @file dom_util.cc
 * @brief utility to use DOMs
 */

#include "util.h"

namespace xmppd {
    Glib::ustring dom_util::serialize_node(const xmlpp::Node& node, const std::map<Glib::ustring, Glib::ustring>& ns_replacements, const std::map<Glib::ustring, Glib::ustring>& known_namespaces) {
	std::map<Glib::ustring, Glib::ustring> ignored;
	return serialize_node(node, ns_replacements, known_namespaces, ignored);
    }

    Glib::ustring dom_util::serialize_node(const xmlpp::Node& node, const std::map<Glib::ustring, Glib::ustring>& ns_replacements, const std::map<Glib::ustring, Glib::ustring>& known_namespaces, std::map<Glib::ustring, Glib::ustring>& now_defined_namespaces_out) {

	// try to serialize as an element
	try {
	    const xmlpp::Element& element = dynamic_cast<const xmlpp::Element&>(node);

	    now_defined_namespaces_out = known_namespaces;
	    std::set<Glib::ustring> ns_definitions_at_this_level;

	    std::ostringstream result;
	    result << "<";

	    // using a prefix?
	    const Glib::ustring& element_ns_prefix = element.get_namespace_prefix();
	    Glib::ustring element_ns_iri = element.get_namespace_uri();
	    if (ns_replacements.find(element_ns_iri) != ns_replacements.end())
		element_ns_iri = ns_replacements.find(element_ns_iri)->second;
	    const Glib::ustring& element_localname = element.get_name();
	    if (element_ns_prefix != "")
		result << element_ns_prefix << ":";

	    // write the element name
	    result << element_localname;

	    // do we have to declare a namespace prefix?
	    if (now_defined_namespaces_out.find(element_ns_prefix) == now_defined_namespaces_out.end() || now_defined_namespaces_out[element_ns_prefix] != element_ns_iri) {
		now_defined_namespaces_out[element_ns_prefix] = element_ns_iri;
		ns_definitions_at_this_level.insert(element_ns_prefix);
		if (element_ns_prefix == "")
		    result << " xmlns='" << xmlescape(element_ns_iri) << "'";
		else
		    result << " xmlns:" << element_ns_prefix << "='" << xmlescape(element_ns_iri) << "'";
	    }

	    // serialize attributes
	    const std::list<xmlpp::Attribute*>& attributes = element.get_attributes();
	    std::list<xmlpp::Attribute*>::const_iterator p;
	    for (p = attributes.begin(); p != attributes.end(); ++p) {
		// serializing might fail if namespace is not declared
		try {
		    const Glib::ustring& attribute_string = serialize_node(**p, ns_replacements, now_defined_namespaces_out);
		    result << " " << attribute_string;
		} catch (...) {
		    const Glib::ustring& attribute_ns_prefix = (*p)->get_namespace_prefix();
		    Glib::ustring attribute_ns_iri = (*p)->get_namespace_uri();
		    if (ns_replacements.find(attribute_ns_iri) != ns_replacements.end())
			attribute_ns_iri = ns_replacements.find(attribute_ns_iri)->second;

		    // is it possible to define this prefix?
		    if (ns_definitions_at_this_level.find(attribute_ns_prefix) != ns_definitions_at_this_level.end()) {
			// we cannot have two different declarations at the same level
			throw;
		    }

		    // define the prefix
		    now_defined_namespaces_out[attribute_ns_prefix] = attribute_ns_iri;
		    ns_definitions_at_this_level.insert(attribute_ns_prefix);
		    result << " xmlns:" << attribute_ns_prefix << "='" << xmlescape(attribute_ns_iri) << "'";

		    // serialization of the attribute should now work
		    const Glib::ustring& attribute_string = serialize_node(**p, ns_replacements, now_defined_namespaces_out);
		    result << " " << attribute_string;
		}
	    }

	    // check if there are children
	    const std::list<xmlpp::Node*>& nodes = element.get_children();

	    // close start tag, if there are no children, we combine it with the end tag
	    if (nodes.empty()) {
		result << "/>";
		return result.str();
	    }
	    result << ">";

	    // serialize the children
	    std::list<xmlpp::Node*>::const_iterator np;
	    for (np = nodes.begin(); np != nodes.end(); ++np) {
		result << serialize_node(**np, ns_replacements, now_defined_namespaces_out);
	    }

	    // write the end tag
	    result << "</";
	    if (element_ns_prefix != "")
		result << element_ns_prefix << ":";
	    result << element_localname << ">";

	    // return what we constructed
	    return result.str();
	} catch (std::bad_cast) {
	    // it is no element
	}

	// try to serialize as a text node
	try {
	    const xmlpp::TextNode& textnode = dynamic_cast<const xmlpp::TextNode&>(node);

	    // return the escaped content
	    return xmlescape(textnode.get_content());
	} catch (std::bad_cast) {
	    // it is no text node
	}

	// try to serialize as an attribute
	try {
	    const xmlpp::Attribute& attribute = dynamic_cast<const xmlpp::Attribute&>(node);

	    const Glib::ustring& localname = attribute.get_name();
	    Glib::ustring ns_iri = attribute.get_namespace_uri();
	    const Glib::ustring& ns_prefix = attribute.get_namespace_prefix();
	    if (ns_replacements.find(ns_iri) != ns_replacements.end())
		ns_iri = ns_replacements.find(ns_iri)->second;

	    std::ostringstream result;

	    if (ns_prefix != "") {
		std::map<Glib::ustring, Glib::ustring>::const_iterator prefix_definition = known_namespaces.find(ns_prefix);
		if (prefix_definition == known_namespaces.end() || prefix_definition->second != ns_iri) {
		    throw std::string("cannot serialize attribute due to namespace prefix problem");
		}

		result << ns_prefix << ":";
	    }
	    result << localname << "='" << xmlescape(attribute.get_value()) << "'";

	    return result.str();
	} catch (std::bad_cast) {
	    // it is no attribute node
	}

	throw std::string("Trying to serialize unknown XML node");
    }

    Glib::ustring dom_util::xmlescape(Glib::ustring str) {
	Glib::ustring::size_type pos;

	// escape the & sign
	for (pos = str.find("&"); pos != Glib::ustring::npos; pos = str.find("&", pos+1)) {
	    str.replace(pos, 1, "&amp;");
	}

	// escape the < sign
	for (pos = str.find("<"); pos != Glib::ustring::npos; pos = str.find("<", pos+1)) {
	    str.replace(pos, 1, "&lt;");
	}

	// escape the > sign
	for (pos = str.find(">"); pos != Glib::ustring::npos; pos = str.find(">", pos+1)) {
	    str.replace(pos, 1, "&gt;");
	}

	// escape the ' sign
	for (pos = str.find("'"); pos != Glib::ustring::npos; pos = str.find("'", pos+1)) {
	    str.replace(pos, 1, "&apos;");
	}

	// escape the " sign
	for (pos = str.find("\""); pos != Glib::ustring::npos; pos = str.find("\"", pos+1)) {
	    str.replace(pos, 1, "&quot;");
	}

	return str;
    }
}
