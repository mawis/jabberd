/*
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2007 Matthias Wimmer
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
 * @file expat.cc
 * @brief reading/writing xmlnodes from/to files, reading xmlnodes from strings
 *
 * This file implements some tools for the xmlnode implementation in xmlnode.c
 *
 * The name of this file is confusing. This file does not contain the expat
 * implementation. It contains some code that uses expat to parse XML and
 * build xmlnodes.
 *
 * @note jabberd14's codebase up to jabberd 1.4.3 had included expat's source.
 * Later versions dynamically link against expat and don't include the code
 * anymore.
 */

#include <jabberdlib.h>

/**
 * structure used to pass information to the expat callbacks
 */
typedef struct {
    xmlnode 		x;		/**< pointer to the xmlnode that is currently read */
    xmppd::ns_decl_list* ns;		/**< list of declared namespace prefixes */
    pool		parse_pool;	/**< memory pool used while parsing */
} _expat_callback_data, *expat_callback_data;

/**
 * callback function used for start elements
 *
 * This function is used internally by expat.c as a callback function
 * given to expat. It will create a new xmlnode and add it to the
 * already created xmlnode tree.
 *
 * @param userdata pointer to the parent xmlnode instance (NULL if this function is called for the root note)
 * @param name name of the starting element
 * @param atts attributes that are contained in the start element
 */
void expat_startElement(void* userdata, const char* name, const char** atts) {
    Glib::ustring qname = name;

    Glib::ustring prefix;
    Glib::ustring ns_iri;
    Glib::ustring local_name;

    /* get the data we are working on */
    expat_callback_data callback_data = static_cast<expat_callback_data>(userdata);

    /* get prefix, iri, and local name of the element */
    Glib::ustring::size_type xmlns_separator_pos = qname.find(XMLNS_SEPARATOR);
    if (xmlns_separator_pos != Glib::ustring::npos) {
	// expat found the namespace IRI for us (this should be the case for a correct stream)
	ns_iri = qname.substr(0, xmlns_separator_pos);
	local_name = qname.substr(xmlns_separator_pos + 1);
	prefix = callback_data->ns->get_nsprefix(ns_iri);
    } else {
	Glib::ustring::size_type colon_pos = qname.find(':');
	if (colon_pos != Glib::ustring::npos) {
	    // expat could not expand the prefix, but there is one

	    // ... be liberal in what you accept ...

	    // start with a guess
	    prefix = qname.substr(0, colon_pos);
	    local_name = qname.substr(colon_pos + 1);
	    ns_iri = "http://jabberd.org/no/clue";

	    // some well known prefixes (but they would have to be declared!)
	    if (prefix == "stream") {
		ns_iri = NS_STREAM;
	    } else if (prefix == "db") {
		ns_iri = NS_DIALBACK;
	    }
	} else {
	    // default namespace, but not declared

	    // again: ... be liberal in what you accept ... (guessing it's 'jabber:server')
	    ns_iri = NS_SERVER;
	    local_name = qname;
	}
    }

    if (callback_data->x == NULL) {
        /* allocate a base node */
	callback_data->x = xmlnode_new_tag_ns(local_name.c_str(), prefix.empty() ? NULL : prefix.c_str(), ns_iri.c_str());
    } else {
	/* insert as child node */
	callback_data->x = xmlnode_insert_tag_ns(callback_data->x, local_name.c_str(), prefix.empty() ? NULL : prefix.c_str(), ns_iri.c_str());
    }
    xmlnode_put_expat_attribs(callback_data->x, atts, *callback_data->ns);
}

/**
 * callback function used for end elements
 *
 * This function is used internally by expat.c as a callback function
 * given to expat. It will complete an xmlnode and update the userdata pointer
 * to point to the node that is parent of the next starting element.
 *
 * @param userdata pointer to the current xmlnode
 * @param name name of the ending element (ignored by this function)
 */
void expat_endElement(void* userdata, const char* name) {
    xmlnode parent = NULL;
    
    /* get the data we are working on */
    expat_callback_data callback_data = (expat_callback_data)userdata;

    /*
    callback_data->x->complete = 1;
    */
    parent = xmlnode_get_parent(callback_data->x);

    /* if it's NULL we've hit the top folks, otherwise back up a level */
    if(parent != NULL)
	callback_data->x = parent;
}

/**
 * callback function for CDATA nodes
 *
 * This function will insert CDATA in an xmlnode
 *
 * @param userdata pointer to the current xmlnode
 * @param s pointer to the CDATA string (not zero terminated!)
 * @param len length of the CDATA string
 */
void expat_charData(void* userdata, const char* s, int len) {
    /* get the data we are working on */
    expat_callback_data callback_data = (expat_callback_data)userdata;

    xmlnode_insert_cdata(callback_data->x, s, len);
}

/**
 * callback function for the beginning of a namespace declaration
 *
 * This function will insert a new namespace prefix in the list of declared namespaces
 *
 * @param userdata XXX
 * @param prefix prefix that gets declared
 * @param iri namespace IRI for this prefix
 */
static void expat_startNamespaceDecl(void *userdata, const XML_Char *prefix, const XML_Char *iri) {
    /* get the data we are working on */
    expat_callback_data callback_data = (expat_callback_data)userdata;

    /* store the new prefix in the list */
    callback_data->ns->update(prefix ? prefix : "", iri ? iri : "");
}

/**
 * callback function for the end of the scope of a declared namespace prefix
 *
 * This function will insert the last occurance of the prefix from the list of declared namespaces
 *
 * @param userdata XXX
 * @param prefix prefix that gets undeclared
 */
static void expat_endNamespaceDecl(void *userdata, const XML_Char *prefix) {
    /* get the data we are working on */
    expat_callback_data callback_data = (expat_callback_data)userdata;

    /* remove the prefix from the list */
    callback_data->ns->delete_last(prefix ? prefix : "");
}

/**
 * create an xmlnode instance (possibly including other xmlnode instances) by parsing a string
 *
 * This function will parse a string containing an XML document and create an xmlnode graph
 *
 * @param str the string containing the XML document (not necessarily zero terminated)
 * @param len the length of the string (without the zero byte, if present)
 * @return the graph of xmlnodes that represent the parsed document, NULL on failure
 */
xmlnode xmlnode_str(const char *str, int len) {
    XML_Parser p;
    _expat_callback_data callback_data = { NULL, NULL, NULL };

    if(NULL == str)
        return NULL;

    callback_data.parse_pool = pool_new();
    callback_data.ns = new xmppd::ns_decl_list();
    p = XML_ParserCreateNS(NULL, XMLNS_SEPARATOR);
    XML_SetUserData(p, &callback_data);
    XML_SetElementHandler(p, expat_startElement, expat_endElement);
    XML_SetCharacterDataHandler(p, expat_charData);
    XML_SetNamespaceDeclHandler(p, expat_startNamespaceDecl, expat_endNamespaceDecl);
    if(!XML_Parse(p, str, len, 1)) {
        xmlnode_free(callback_data.x);
	callback_data.x = NULL;
    }
    XML_ParserFree(p);
    pool_free(callback_data.parse_pool);
    delete callback_data.ns;
    return callback_data.x; /* return the xmlnode x points to */
}

/**
 * create an xmlnode instance (possibly including other xmlnode instances) by parsing a file
 *
 * This function will parse a file containing an XML document and create an xmlnode graph
 *
 * @param file the filename
 * @return the graph of xmlnodes that represent the parsed document, NULL on failure
 */
xmlnode xmlnode_file(const char *file) {
    XML_Parser p;
    _expat_callback_data callback_data = { NULL, NULL, NULL };
    char buf[BUFSIZ];
    int done, fd, len;

    if(NULL == file)
        return NULL;

    fd = open(file,O_RDONLY);
    if(fd < 0)
        return NULL;

    callback_data.parse_pool = pool_new();
    callback_data.ns = new xmppd::ns_decl_list();
    p = XML_ParserCreateNS(NULL, XMLNS_SEPARATOR);
    XML_SetUserData(p, &callback_data);
    XML_SetElementHandler(p, expat_startElement, expat_endElement);
    XML_SetCharacterDataHandler(p, expat_charData);
    XML_SetNamespaceDeclHandler(p, expat_startNamespaceDecl, expat_endNamespaceDecl);
    do {
        len = read(fd, buf, BUFSIZ);
        done = len < BUFSIZ;
        if(!XML_Parse(p, buf, len, done))
        {
            xmlnode_free(callback_data.x);
	    callback_data.x = NULL;
            done = 1;
        }
    } while (!done);

    XML_ParserFree(p);
    close(fd);
    pool_free(callback_data.parse_pool);
    delete callback_data.ns;
    return callback_data.x; /* return the xmlnode x points to */
}

/**
 * get message why parsing of a file failed
 *
 * This function can be used to get a textual message why parsing an XML file failed.
 *
 * @param file the filename
 * @return pointer to a message why parsing failed, NULL if parsing did not fail
 */
char const* xmlnode_file_borked(char const* file) {
    XML_Parser p;
    char buf[BUFSIZ];
    static char err[1024];
    int fd, len, done=0;

    if(NULL == file)
        return "no file specified";

    fd = open(file,O_RDONLY);
    if(fd < 0)
        return "unable to open file";

    p = XML_ParserCreateNS(NULL, XMLNS_SEPARATOR);
    while(!done)
    {
        len = read(fd, buf, BUFSIZ);
        done = len < BUFSIZ;
        if(!XML_Parse(p, buf, len, done))
        {
            snprintf(err, sizeof(err), "%s at line %ld and column %ld", XML_ErrorString(XML_GetErrorCode(p)), XML_GetErrorLineNumber(p), XML_GetErrorColumnNumber(p));
            XML_ParserFree(p);
            close(fd);
            return err;
        }
    }

    return NULL;
}

/**
 * write an xmlnode to a file (without a size limit)
 *
 * @param file the target file
 * @param node the xmlnode that should be written
 * @return 1 on success, -1 on failure
 */
int xmlnode2file(char const* file, xmlnode node)
{
    return xmlnode2file_limited(file, node, 0);
}

/**
 * write an xmlnode to a file, limited by size
 *
 * @param file the target file
 * @param node the xmlnode that should be written
 * @param sizelimit the maximum length of the file to be written
 * @return 1 on success, 0 if failed due to size limit, -1 on failure
 */
int xmlnode2file_limited(char const* file, xmlnode node, size_t sizelimit) {
    char *doc;
    int fd, i;
    size_t doclen;

    /* sanity checks */
    if(file == NULL || node == NULL)
        return -1;

    /* serialize the document ... we need to know the size of it */
    doc = xmlnode_serialize_string(node, xmppd::ns_decl_list(), 0);
    doclen = j_strlen(doc);

    /* is it to big? (23 is the size of the XML declaration and the trailing newline in the file) */
    if (sizelimit > 0 && (doclen + 23) > sizelimit) {
	close(fd);
	return 0;
    }

    std::ostringstream ftmp;
    ftmp << file << ".t.m.p";
    fd = open(ftmp.str().c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0)
        return -1;

    /* write XML declaration, remove temp file on failure */
    i = write(fd, "<?xml version='1.0'?>\n", 22);
    if (i < 0) {
	close(fd);
	unlink(ftmp.str().c_str());
	return -1;
    }

    /* write XML content, remove temp file on failure */
    i = write(fd, doc, doclen);
    if (i < 0) {
	close(fd);
	unlink(ftmp.str().c_str());
        return -1;
    }

    /* write a closing newline */
    i = write(fd, "\n", 1);
    if (i < 0) {
	close(fd);
	unlink(ftmp.str().c_str());
        return -1;
    }

    /* close the file */
    close(fd);

    /* replace the old file with the new one */
    if(rename(ftmp.str().c_str(), file) < 0) {
        unlink(ftmp.str().c_str());
        return -1;
    }

    /* return successful */
    return 1;
}

/**
 * append attributes in the expat format to an existing xmlnode
 *
 * @param owner where to add the attributes
 * @param atts the attributes in expat format (even indexes are the attribute names, odd indexes the values)
 * @param nslist list of currently defined prefixes for namespace IRIs
 */
void xmlnode_put_expat_attribs(xmlnode owner, const char** atts, xmppd::ns_decl_list& nslist) {
    int i = 0;
   
    // sanity check
    if (atts == NULL)
	return;

    for (; atts[i] != '\0'; i += 2) {
	// copy qname and the value to a ustring we can handle better
	Glib::ustring qname(atts[i]);
	Glib::ustring attribute_value(atts[i+1]);

	Glib::ustring prefix;
	Glib::ustring ns_iri;
	Glib::ustring local_name;

	// get prefix, iri, and local name of the element
	Glib::ustring::size_type xmlns_separator_pos = qname.find(XMLNS_SEPARATOR);
	if (xmlns_separator_pos != Glib::ustring::npos) {
	    // expat found the namespace IRI for us (this should be the case for a correct stream)
	    ns_iri = qname.substr(0, xmlns_separator_pos);
	    local_name = qname.substr(xmlns_separator_pos + 1);
	    prefix = nslist.get_nsprefix(ns_iri);
	} else {
	    Glib::ustring::size_type colon_pos = qname.find(':');
	    if (colon_pos != Glib::ustring::npos) {
		// expat could not expand the prefix, but there is one

		// ... be liberal in what you accept ...

		// start with a guess
		prefix = qname.substr(0, colon_pos);
		local_name = qname.substr(colon_pos + 1);
		ns_iri = "http://jabberd.org/no/clue";

		// some well known prefixes (but they would have to be declared!)
		if (prefix == "stream") {
		    ns_iri = NS_STREAM;
		} else if (prefix == "db") {
		    ns_iri = NS_DIALBACK;
		}
	    } else {
		local_name = qname;
	    }
	}

	// add attribute to the node
	xmlnode_put_attrib_ns(owner, local_name.c_str(), prefix.empty() ? NULL : prefix.c_str(), ns_iri.empty() ? NULL : ns_iri.c_str(), attribute_value.c_str());
    }
}
