/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "JOSL").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the JOSL. You
 * may obtain a copy of the JOSL at http://www.jabber.org/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the JOSL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the JOSL
 * for the specific language governing rights and limitations under the
 * JOSL.
 *
 * Copyrights
 *
 * This file is Copyright (C) 2006 Matthias Wimmer
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 or later (the "GPL"), in which case
 * the provisions of the GPL are applicable instead of those above.  If you
 * wish to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the JOSL,
 * indicate your decision by deleting the provisions above and replace them
 * with the notice and other provisions required by the GPL.  If you do not
 * delete the provisions above, a recipient may use your version of this file
 * under either the JOSL or the GPL. 
 * 
 * --------------------------------------------------------------------------*/

#include <map>
#include <string>
#include <locale>

#include "jabberdlib.h"

/**
 * the messages class is used get access messages in different languages
 */
class messages {
    public:
	static messages static_messages;
	void set_mapping(const std::string& lang, const std::string& locale_name);
	std::string get(const std::string& lang, const char* message);
    private:
	std::map<std::string, const std::messages<char>*> messages_by_lang;
	std::map<std::string, std::messages<char>::catalog> catalog_by_lang;
};

messages messages::static_messages;

void messages::set_mapping(const std::string& lang, const std::string& locale_name) {
    // get the locale
    const std::locale locale(locale_name.c_str());

    // get the messages facet
    const std::messages<char>& messages = std::use_facet<std::messages<char> >(locale);

    // (try to) open the catalog
    std::messages<char>::catalog catalog = messages.open(PACKAGE, locale, LOCALEDIR);
    if (catalog == -1) {
	return;
    }

    // put both (facet and catalog in their) map
    messages_by_lang[lang] = &messages;
    catalog_by_lang[lang] = catalog;
}

std::string messages::get(const std::string& lang, const char* message) {
    try {
	// sanity check
	if (message == NULL)
	    return get(lang, "(null)");

	// do we have a catalog for this language?
	if (catalog_by_lang.find(lang) == catalog_by_lang.end())
	    return message;
	
	const std::messages<char>* messages = messages_by_lang[lang];
	if (messages == NULL)
	    return message;

	return messages->get(catalog_by_lang[lang], 0, 0, message);
    } catch (...) {
	// if we cannot load a translation, we return the original string
	return message;
    }
}

extern "C" {
    void messages_set_mapping(const char* lang, const char* locale_name) {
	// sanity check
	if (lang == NULL || locale_name == NULL)
	    return;

	messages::static_messages.set_mapping(lang, locale_name);
    }

    const char* messages_get(const char* lang, const char* message) {
	static std::string last_result;

	// sanity check
	if (lang == NULL)
	    return message;

	// get message
	last_result = messages::static_messages.get(lang, message);
	return last_result.c_str();
    }
}
