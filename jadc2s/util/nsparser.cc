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
 * @file nsparser.cc
 * @brief Namespace aware parsing of XML data
 */

#include "util.h"

namespace xmppd {
    nsparser::nsparser(bool use_get_entity) : xmlpp::SaxParser(use_get_entity), pass_ns_definitions(false), open_elements(0) {
    }

    void nsparser::on_start_element_ns(const Glib::ustring& localname, const Glib::ustring& ns_prefix, const Glib::ustring& ns_iri, const AttributeNSList& attributes) {
    }

    void nsparser::on_end_element_ns(const Glib::ustring& localname, const Glib::ustring& ns_prefix, const Glib::ustring& ns_iri) {
    }

    void nsparser::on_start_element(const Glib::ustring& name, const AttributeList& attributes) {
	AttributeNSList ns_attributes;

	// one more open element
	open_elements++;

	// get the namespace mappings we had at the parent level
	std::map< Glib::ustring, std::pair<Glib::ustring, int> > current_ns_mappings;
	if (!ns_mappings.empty()) {
	    current_ns_mappings = ns_mappings.top();
	} else {
	    // default namespace prefix mappings
	    current_ns_mappings[""] = std::pair<Glib::ustring, int>(nsparser::NS_EMPTY, 0);
	    current_ns_mappings["xml"] = std::pair<Glib::ustring, int>(nsparser::NS_XML, 0);
	    current_ns_mappings["xmlns"] = std::pair<Glib::ustring, int>(nsparser::NS_XMLNS, 0);
	}

	// update the mappings from what attributes of this start element define
	// and copy attributes, that do not define a namespace to the ns_attributes deque
	std::deque<xmlpp::SaxParser::Attribute>::const_iterator p;
	for (p = attributes.begin(); p != attributes.end(); ++p) {
	    AttributeNS current_attribute(p->name, "", "", p->value);
	    Glib::ustring::size_type colon_pos = p->name.find(':');

	    if (colon_pos != Glib::ustring::npos) {
		// prefixed name
		current_attribute.ns_prefix = p->name.substr(0, colon_pos);
		current_attribute.localname = p->name.substr(colon_pos+1);
	    }

	    if (current_attribute.localname == "xmlns" && current_attribute.ns_prefix == "") {
		// new definition of the default namespace
		current_attribute.ns_iri = nsparser::NS_XMLNS;
		current_ns_mappings[""].first = current_attribute.value;
		current_ns_mappings[""].second = open_elements;
		if (!pass_ns_definitions) {
		    continue;
		}
	    } else if (current_attribute.ns_prefix == "xmlns") {
		// new definition of a namespace prefix
		current_attribute.ns_iri = nsparser::NS_XMLNS;
		current_ns_mappings[current_attribute.localname].first = current_attribute.value;
		current_ns_mappings[current_attribute.localname].second = open_elements;;
		if (!pass_ns_definitions) {
		    continue;
		}
	    }

	    ns_attributes.push_back(current_attribute);
	}

	// push the new mappings to the stack
	ns_mappings.push(current_ns_mappings);

	// update non namespace-defining attributes to have their namespace IRI
	AttributeNSList::iterator p2;
	for (p2 = ns_attributes.begin(); p2 != ns_attributes.end(); ++p2) {
	    // namespace defining attributes already got their IRI
	    if (p2->ns_iri != "")
		continue;

	    // attributes without a prefix are in the empty namespace, not in the default namespace!
	    if (p2->ns_prefix == "")
		continue;

	    // for all other attributes (not defining a namespace itself and having a ns prefix) check if that prefix is defined
	    if (current_ns_mappings.find(p2->ns_prefix) == current_ns_mappings.end()) {
		throw Glib::ustring("Found attribute using undefined namespace prefix "+p2->ns_prefix);
	    }
	    // and set the ns_iri in the attribute definition
	    p2->ns_iri = current_ns_mappings[p2->ns_prefix].first;
	}

	// split the name of the start element
	Glib::ustring localname = name;
	Glib::ustring ns_prefix;
	Glib::ustring::size_type colon_pos = name.find(':');
	if (colon_pos != Glib::ustring::npos) {
	    // prefixed name
	    ns_prefix = name.substr(0, colon_pos);
	    localname = name.substr(colon_pos+1);
	}

	// get the namespace IRI for the element
	if (current_ns_mappings.find(ns_prefix) == current_ns_mappings.end()) {
	    throw Glib::ustring("Found start element using undefined namespace prefix "+ns_prefix);
	}
	Glib::ustring ns_iri = current_ns_mappings[ns_prefix].first;

	// call the namespace aware method
	on_start_element_ns(localname, ns_prefix, ns_iri, ns_attributes);
    }

    void nsparser::on_end_element(const Glib::ustring& name) {
	// split the name of the end element
	Glib::ustring localname = name;
	Glib::ustring ns_prefix;
	Glib::ustring::size_type colon_pos = name.find(':');
	if (colon_pos != Glib::ustring::npos) {
	    // prefixed name
	    ns_prefix = name.substr(0, colon_pos);
	    localname = name.substr(colon_pos+1);
	}

	Glib::ustring ns_iri = (ns_mappings.top())[ns_prefix].first;

	// call the namespace aware method
	on_end_element_ns(localname, ns_prefix, ns_iri);

	// pop a level of namespace mappings from the stack as we left the corresponding element
	ns_mappings.pop();

	// one open element less
	open_elements--;
    }

    const Glib::ustring nsparser::NS_XMLNS = "http://www.w3.org/2000/xmlns/";
    const Glib::ustring nsparser::NS_EMPTY = "";
    const Glib::ustring nsparser::NS_XML = "http://www.w3.org/XML/1998/namespace";
}
