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
 * @file xmlistream.cc
 * @brief Implementation of an XML stream, that gets partitioned at the level of second level nodes.
 */

#include "util.h"

namespace xmppd {
    xmlistream::xmlistream(bool use_get_entity) : nsparser(use_get_entity), maxdepth(10000) {
    }

    void xmlistream::on_error(const Glib::ustring& text) {
	signal_on_close(true, text);
    }

    void xmlistream::on_start_element_ns(const Glib::ustring& localname, const Glib::ustring& ns_prefix, const Glib::ustring& ns_iri, const AttributeNSList& attributes) {
	// is it the stream root we are receiving?
	// handle this in another method
	if (open_elements == 1) {
	    on_start_element_root(localname, ns_prefix, ns_iri, attributes);
	    return;
	}

	// if we are too deep in elements, signal an error
	if (open_elements > maxdepth)
	    on_error("maximum XML depth reached");

	// not the root element, building stanzas
	
	// does the namespace have to be mapped?
	Glib::ustring mapped_ns_iri;
	if (namespace_replacements.find(ns_iri) != namespace_replacements.end())
	    mapped_ns_iri = namespace_replacements[ns_iri];
	else
	    mapped_ns_iri = ns_iri;

	// create the new element
	xmlpp::Element* new_element = current_element.top()->add_child(localname);

	// check if the new element has a new namespace, and declare if necessary
	if (current_element.top()->get_namespace_uri() != mapped_ns_iri)
	    new_element->set_namespace_declaration(mapped_ns_iri);

	// set the namespace of the new element
	// (XXX: libxml++ does not set any namespace (not even the default namespace)
	// if add_element is called with the empty namespace prefix. IMHO this is a
	// but in libxml++, and I want to write a patch for it. For now setting
	// the namespace prefix to "" using set_namespace() is a workaround.)
	new_element->set_namespace("");

	// make the new element the current one
	current_element.push(new_element);

	// copy the attributes to the new element
	add_attributes_to_current_element(attributes);
    }

    void xmlistream::on_start_element_root(const Glib::ustring& localname, const Glib::ustring& ns_prefix, const Glib::ustring& ns_iri, const AttributeNSList& attributes) {
	xmlpp::Element* root_element = NULL;

	// create the document root element
	if (namespace_replacements.find(ns_iri) != namespace_replacements.end())
	    root_element = stream_document.create_root_node(localname, namespace_replacements[ns_iri], ns_prefix);
	else
	    root_element = stream_document.create_root_node(localname, ns_iri, ns_prefix);

	// we shout have gotten a real root_element pointer
	if (root_element == NULL)
	    throw Glib::ustring("We could not create a root element ("+ns_prefix+":"+localname+"/"+ns_iri+")");

	// If our root element is not in the default namespace, we copy the default namespace if it has been declared
	if (ns_prefix != "" && ns_mappings.top()[""].second == 2) {
	    root_element->set_namespace_declaration(ns_mappings.top()[""].first, "");
	}

	// this is the first element in our element stack
	current_element.push(root_element);

	// copy attributes to this new element
	add_attributes_to_current_element(attributes);

	// fire the signal_on_root event
	signal_on_root(stream_document, *root_element, ns_iri);
    }

    void xmlistream::add_attributes_to_current_element(const AttributeNSList& attributes) {
	AttributeNSList::const_iterator p;
	for (p=attributes.begin(); p!=attributes.end(); ++p) {
	    // some prefixes never have to be declared
	    if (p->ns_prefix != "" && p->ns_prefix != "xml" && p->ns_prefix != "xmlns") {
		if (namespace_replacements.find(p->ns_iri) != namespace_replacements.end())
		    current_element.top()->set_namespace_declaration(namespace_replacements[p->ns_iri], p->ns_prefix);
		else
		    current_element.top()->set_namespace_declaration(p->ns_iri, p->ns_prefix);
	    }
	    // copy the attribute, we can now be sure that the namespace prefix either has not to be declared or is already declared
	    current_element.top()->set_attribute(p->localname, p->value, p->ns_prefix);
	}
    }

    void xmlistream::on_end_element_ns(const Glib::ustring& localname, const Glib::ustring& ns_prefix, const Glib::ustring& ns_iri) {
	xmlpp::Element* stanza = NULL;

	// is the stanza complete now?
	if (open_elements == 2) {
	    // keep pointer to the stanza for removing it later
	    stanza = current_element.top();

	    // fire the signal_on_stanza event
	    signal_on_stanza(stream_document, *stanza);
	}

	// the parent of the previous element node is the new current element again now
	current_element.pop();

	// if the stanza is completed, remove it now from the document
	if (open_elements == 2 && stanza != NULL)
	    current_element.top()->remove_child(stanza);
    }

    void xmlistream::on_characters(const Glib::ustring& characters) {
	// ignore any character data outside of stanzas
	if (open_elements < 2)
	    return;

	// add content to the current element
	current_element.top()->add_child_text(characters);
    }

    void xmlistream::set_namespace_replacement(const Glib::ustring& replaced, const Glib::ustring& replacement) {
	namespace_replacements[replaced] = replacement;
    }
}
