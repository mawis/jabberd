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
 * @file xmlostream.cc
 * @brief Implementation of an outgoing XML stream
 */

#include "util.h"

namespace xmppd {
    xmlostream::xmlostream(const xmlpp::Document& stream_root, std::map<Glib::ustring, Glib::ustring> ns_replacements) : stream_is_closed(false), ns_replacements(ns_replacements) {
	// create a list of namespace prefixes, that are automatically bound to their IRIs
	std::map<Glib::ustring, Glib::ustring> standard_ns_prefixes;
	standard_ns_prefixes[""] = nsparser::NS_EMPTY;
	standard_ns_prefixes["xml"] = nsparser::NS_XML;
	standard_ns_prefixes["xmlns"] = nsparser::NS_XMLNS;

	// get the root node of the document
	xmlpp::Element* root_node = stream_root.get_root_node();
	if (root_node == NULL) {
	    throw std::invalid_argument("stream_root document does not contain nodes (when constructing xmlostream)");
	}

	// format the stream root element, and the closing tag for it
	Glib::ustring root_element = dom_util::serialize_node(*root_node, ns_replacements, standard_ns_prefixes, namespaces_on_root);
	Glib::ustring::size_type tag_end_pos = root_element.find(">");
	root_element.erase(tag_end_pos);
	if (root_element[root_element.length()-1] == '/')
	    root_element.erase(root_element.length()-1);
	stream_close_tag = root_element;
	root_element = "<?xml version='1.0'?>"+root_element+">";
	Glib::ustring::size_type end_of_name_pos = stream_close_tag.find(" ");
	if (end_of_name_pos != Glib::ustring::npos)
	    stream_close_tag.erase(end_of_name_pos);
	stream_close_tag.insert(1, "/");
	stream_close_tag += ">";

	// create a chunk containing the root element start tag
	pointer<chunk> to_write = new chunk;
	to_write->bytes = root_element;

	// append the chunk to what needs to get written
	waiting_stanzas.push(to_write);
    }

    void xmlostream::send_stanza(const xmlpp::Document& stanza_document, bool want_back_on_error) {
	// check that the stream is still open
	if (stream_is_closed)
	    throw std::domain_error("data cannot be written on a closed xmlostream");

	// check that there is a stanza
	xmlpp::Element* original_root = stanza_document.get_root_node();
	if (original_root == NULL)
	    throw std::domain_error("there is no root element in the document passed to send_stanza");
	std::list<xmlpp::Node*> stanza_nodes = original_root->get_children("");
	if (stanza_nodes.empty())
	    throw std::domain_error("the document passed to send_stanza contains no stanzas");

	// create a chunk that will hold the new stanza
	pointer<chunk> stanza = new chunk;

	// copy over the stanza XML data
	if (want_back_on_error) {
	    stanza->xml = new xmlpp::Document;
	    stanza->xml->create_root_node_by_import(original_root);
	}

	// serialize the stanza(s) to their textual representation
	std::list<xmlpp::Node*>::const_iterator p;
	for (p = stanza_nodes.begin(); p != stanza_nodes.end(); ++p) {
	    stanza->bytes += dom_util::serialize_node(*(*p), ns_replacements, namespaces_on_root);
	}

	// append the chunk to what needs to get written
	waiting_stanzas.push(stanza);
	stanza = NULL;

	// try if the data can be written
	try_writing();
    }

    void xmlostream::try_writing() {
	while (!waiting_stanzas.empty()) {
	    pointer<chunk> current_stanza = waiting_stanzas.front();

	    // try writing the current stanza
	    write_handler(current_stanza->bytes);

	    // if it wasn't possible to write the complete stanza, stop this try
	    if (current_stanza->bytes.length() > 0) {
		break;
	    }

	    // this stanza has been written, remove it from the queue
	    waiting_stanzas.pop();
	}
    }

    void xmlostream::close() {
	// check that the stream previously still has been open
	if (stream_is_closed)
	    throw std::domain_error("a xmlostream cannot be closed twice");

	// create a chunk for the end tag
	pointer<chunk> stream_end_tag = new chunk;

	// copy the bytes in
	stream_end_tag->bytes = stream_close_tag;

	// append the chunk to what needs to get written
	waiting_stanzas.push(stream_end_tag);
	stream_end_tag = NULL;

	// try if the data can be written
	try_writing();
    }
}
