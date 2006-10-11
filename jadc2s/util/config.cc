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
#include <xercesc/util/PlatformUtils.hpp>
#include <xercesc/util/XMLString.hpp>
#include <xercesc/sax2/XMLReaderFactory.hpp>
#include <xercesc/util/TransService.hpp>
// #include <xercesc/sax2/SAX2XMLReader.hpp>
// #include <xercesc/sax2/DefaultHandler.hpp>
#include <iostream>

namespace xmppd {

    configuration::configuration(const std::string& configfile) : transcoder(NULL) {
	// Initialize Xerces to parse the file
	try {
	    XERCES_CPP_NAMESPACE_QUALIFIER XMLPlatformUtils::Initialize("");
	} catch (const XERCES_CPP_NAMESPACE_QUALIFIER XMLException& xml_exception) {
	    std::cerr << "Could not initialize Xerces-C\nError message is: ";
	    char* message = XERCES_CPP_NAMESPACE_QUALIFIER XMLString::transcode(xml_exception.getMessage());
	    std::cerr << message << std::endl;
	    XERCES_CPP_NAMESPACE_QUALIFIER XMLString::release(&message);
	    return;
	}

	// get the transcoder
	XERCES_CPP_NAMESPACE_QUALIFIER XMLTransService::Codes failReason;
	transcoder = XERCES_CPP_NAMESPACE_QUALIFIER XMLPlatformUtils::fgTransService->makeNewTranscoderFor("UTF-8", failReason, 4*1024);

	// create a parser instance
	xmppd::pointer<XERCES_CPP_NAMESPACE_QUALIFIER SAX2XMLReader> parser = XERCES_CPP_NAMESPACE_QUALIFIER XMLReaderFactory::createXMLReader();

	// set handlers to this instance
	parser->setContentHandler(this);
	parser->setErrorHandler(this);

	// parse the file
	try {
	    parser->parse(configfile.c_str());
	} catch (const XERCES_CPP_NAMESPACE_QUALIFIER XMLException& to_catch) {
	    char *message = XERCES_CPP_NAMESPACE_QUALIFIER XMLString::transcode(to_catch.getMessage());
	    std::cerr << "XMLException in parsing file " << configfile << ":\n";
	    std::cerr << message << std::endl;
	    XERCES_CPP_NAMESPACE_QUALIFIER XMLString::release(&message);
	} catch (const XERCES_CPP_NAMESPACE_QUALIFIER SAXParseException& to_catch) {
	    char *message = XERCES_CPP_NAMESPACE_QUALIFIER XMLString::transcode(to_catch.getMessage());
	    std::cerr << "SAXParseException in parsing file " << configfile << ":\n";
	    std::cerr << message << std::endl;
	    XERCES_CPP_NAMESPACE_QUALIFIER XMLString::release(&message);
	}
    }

    configuration::~configuration() {
	transcoder = NULL;
	XERCES_CPP_NAMESPACE_QUALIFIER XMLPlatformUtils::Terminate();
    }

    void configuration::endElement(const XMLCh *const uri, const XMLCh *const localname, const XMLCh *const qname) {
	configuration_entry new_entry;
	new_entry.value = parse_buffer;
	parse_buffer = "";

	operator[](path_stack.top()).push_back(new_entry);

	path_stack.pop();
    }

    void configuration::startElement(const XMLCh *const uri, const XMLCh *const localname, const XMLCh *const qname, const XERCES_CPP_NAMESPACE_QUALIFIER Attributes &attrs) {
	// push new path to a possible value to the path_stack
	std::string new_path;
	if (!path_stack.empty()) {
	    if (path_stack.top() == "") {
		new_path = convert_xmlch_to_utf8(localname);
	    } else {
		new_path = path_stack.top() + "." + convert_xmlch_to_utf8(localname);
	    }
	}

	path_stack.push(new_path);

	parse_buffer = "";
    }

    void configuration::characters(const XMLCh *const chars, const unsigned int length) {
	if (length > 0)
	    parse_buffer += convert_xmlch_to_utf8(chars, length);
    }

    std::string configuration::convert_xmlch_to_utf8(const XMLCh *const src, unsigned int length) {
	const XMLCh* ptr = src;
	if (length == 0)
	    length = XERCES_CPP_NAMESPACE_QUALIFIER XMLString::stringLen(src);
	std::string result;

	while (length > 0) {
	    XMLByte buffer[4*1024];
	    unsigned int eaten = 0;

	    unsigned int bytes_written = transcoder->transcodeTo(ptr, length, buffer, 4*1024, eaten, XERCES_CPP_NAMESPACE_QUALIFIER XMLTranscoder::UnRep_Throw);

	    if (eaten == 0) {
		throw std::string("Cannot convert XML string to UTF-8");
	    }
	    ptr += eaten;
	    length -= eaten;
	    if (bytes_written < 1)
		continue;

	    result += std::string(reinterpret_cast<char*>(buffer), bytes_written);
	}

	return result;
    }

    const std::string& configuration::get_string(const std::string& what) {
	if (find(what) == end())
	    throw std::string("Request for unset configuration setting");

	if (operator[](what).empty())
	    throw std::string("Internal error: empty list in configuration instance.");

	return operator[](what).front().value;
    }

    int configuration::get_integer(const std::string& what) {
	std::istringstream result_stream(get_string(what));
	int result = 0;
	result_stream >> result;
	return result;
    }
}
