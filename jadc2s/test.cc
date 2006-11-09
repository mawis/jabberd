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

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include "util/util.h"
#include <iostream>

void writer(std::string& text) {
    std::cout << text;
    text = "";
}

int main() {
    std::cout << "NOTE: This is currently only testing code. jadc2s (now called\n"
	"xmppd-c2s) is currently rewritten. On production systems revision\n"
	"1287 is the currently recommended version of jadc2s." << std::endl;

    xmlpp::Document* xml_document = new xmlpp::Document;
    xmlpp::Element* root_element = xml_document->create_root_node("stream", "http://etherx.jabber.org/streams", "stream");
    root_element->set_namespace_declaration("jabber:server");
    root_element->set_namespace("stream");
    root_element->set_attribute("version", "1.0");
    root_element->set_attribute("to", "example.com");

    std::map<Glib::ustring, Glib::ustring> ns_replacements;

    xmppd::xmlostream ostream(*xml_document, "jabber:server", ns_replacements);
    ostream.write_handler.connect(sigc::ptr_fun(writer));

    delete xml_document;

    ostream.try_writing();

    // send some stanzas
    for (int i = 0; i<10; i++) {
	xml_document = new xmlpp::Document;
	xmlpp::Element* root_element = xml_document->create_root_node("stream", "http://etherx.jabber.org/streams", "stream");
	root_element->set_namespace_declaration("jabber:server");
	root_element->set_attribute("version", "1.0");
	root_element->set_attribute("to", "example.com");

	xmlpp::Element* message = root_element->add_child("message");
	message->set_namespace("");
	message->set_attribute("to", "foo@example.com");
	message->set_attribute("from", "bar@example.com");
	std::ostringstream id;
	id << i;
	message->set_attribute("id", id.str());
	id.str("");
	xmlpp::Element* body = message->add_child("body");
	body->set_namespace("");
	id << "Message number " << i;
	body->set_child_text(id.str());

	ostream.send_stanza(*xml_document, true);
    }

    ostream.close();

    return 0;
}
