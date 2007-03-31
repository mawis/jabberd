/*
 * Copyrights
 * 
 * Copyright (c) 2006-2007 Matthias Wimmer
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
 * @file messages.cc
 * @brief support for internationalized messages
 *
 * This implements an interface to access message translation catalogs
 */

#include <map>
#include <string>
#include <locale>
#include <stdexcept>

#include "jabberdlib.h"

/**
 * the messages class is used get access messages in different languages
 */
class messages {
    public:
	/**
	 * globally available instance of messages
	 */
	static messages static_messages;

	/**
	 * define a mapping from a language token in XML to a system locale
	 *
	 * @param lang the XML language token
	 * @param locale_name the system locale name
	 */
	void set_mapping(const std::string& lang, const std::string& locale_name);

	/**
	 * get a translated message
	 *
	 * @param lang the language (XML language token) to get the message for
	 * @param message the message to get a translation for
	 * @return the translated message (if available), or same as message
	 */
	std::string get(const std::string& lang, const char* message);
    private:
	/**
	 * mappings from XML language token to system locales
	 */
	std::map<std::string, std::string> locale_by_lang;

	/**
	 * mapping from XML language token to a message catalog instance
	 */
	std::map<std::string, std::messages<char>::catalog> catalog_by_lang;
};

messages messages::static_messages;

void messages::set_mapping(const std::string& lang, const std::string& locale_name) {
    try {
	// get the locale
	const std::locale locale(locale_name.c_str());

	// get the messages facet
	const std::messages<char>& messages = std::use_facet<std::messages<char> >(locale);

	// (try to) open the catalog
	std::messages<char>::catalog catalog = messages.open(PACKAGE, locale, LOCALEDIR);
	if (catalog == -1) {
	    return;
	}

	// put catalog and mapping in the map
	catalog_by_lang[lang] = catalog;
	locale_by_lang[lang] = locale_name;
    } catch (std::runtime_error) {
	// propably the requested system locale does not exist ...
    }
}

std::string messages::get(const std::string& lang, const char* message) {
    try {
	// sanity check
	if (message == NULL)
	    return get(lang, "(null)");

	// do we have a catalog for this language?
	if (catalog_by_lang.find(lang) == catalog_by_lang.end()) {
	    std::string general_language = lang;
	    std::string::size_type dash_pos = general_language.find('-');

	    // maybe it is something like fr-FR and we can also check for fr ...
	    if (dash_pos != std::string::npos) {
		general_language.erase(dash_pos);
		return get(general_language, message);
	    }

	    // no catalog found for this language
	    return message;
	}

	const std::locale locale(locale_by_lang[lang].c_str());
	const std::messages<char>& messages = std::use_facet<std::messages<char> >(locale);

	return messages.get(catalog_by_lang[lang], 0, 0, message);
    } catch (...) {
	// if we cannot load a translation, we return the original string
	return message;
    }
}

/**
 * define a mapping from a language token in XML to a system locale for the static messages instance
 *
 * @param lang the XML language token
 * @param locale_name the system locale name
 */
void messages_set_mapping(const char* lang, const char* locale_name) {
    // sanity check
    if (lang == NULL || locale_name == NULL)
	return;

    messages::static_messages.set_mapping(lang, locale_name);
}

/**
 * get a translated message from the static messages instance
 *
 * @param lang the language (XML language token) to get the message for
 * @param message the message to get a translation for
 * @return the translated message (if available), or same as message
 */
const char* messages_get(const char* lang, const char* message) {
    static std::string last_result;

    // sanity check
    if (lang == NULL)
	return message;

    // get message
    last_result = messages::static_messages.get(lang, message);
    return last_result.c_str();
}
