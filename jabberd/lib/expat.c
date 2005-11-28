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
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
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
 * 
 * --------------------------------------------------------------------------*/

/**
 * @file expat.c
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
    ns_list_item 	first_ns;	/**< first element in the list of declared namespace prefixes */
    ns_list_item 	last_ns;	/**< last element in the list of declared namespace prefixes */
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
    char *prefix = NULL;
    char *ns_iri = NULL;
    char *local_name = NULL;

    /* get the data we are working on */
    expat_callback_data callback_data = (expat_callback_data)userdata;

    /* get prefix, iri, and local name of the element */
    if (strchr(name, XMLNS_SEPARATOR) != NULL) {
	/* expat found the namespace IRI for us */
	ns_iri = pstrdup(callback_data->parse_pool, name);
	local_name = strchr(ns_iri, XMLNS_SEPARATOR);
	local_name[0] = 0;
	local_name++;
	prefix = pstrdup(callback_data->parse_pool, xmlnode_list_get_nsprefix(callback_data->last_ns, ns_iri));
    } else if (strchr(name, ':') != NULL) {
	/* expat could not expand the prefix, it's not declared */

	/* ... be liberal in what you accept ... */

	/* start with a guess */
	prefix = pstrdup(callback_data->parse_pool, name);
	local_name = strchr(prefix, ':');
	local_name[0] = 0;
	local_name++;
	ns_iri = "http://jabberd.org/no/clue";

	/* some well known prefixes (but they would have to been declared!) */
	if (j_strcmp(prefix, "stream") == 0) {
	    ns_iri = NS_STREAM;
	} else if (j_strcmp(prefix, "db") == 0) {
	    ns_iri = NS_DIALBACK;
	}
    } else {
	/* default namespace, but not declared */

	/* ... be liberal in what you accept ... (guessing it's 'jabber:server') */
	prefix = NULL;
	ns_iri = "jabber:server";
	local_name = pstrdup(callback_data->parse_pool, name);
    }

    if (prefix != NULL && prefix[0] == '\0')
	prefix = NULL;

    if (callback_data->x == NULL) {
        /* allocate a base node */
	callback_data->x = xmlnode_new_tag_ns(local_name, prefix, ns_iri);
    } else {
	/* insert as child node */
	callback_data->x = xmlnode_insert_tag_ns(callback_data->x, local_name, prefix, ns_iri);
    }
    xmlnode_put_expat_attribs(callback_data->x, atts);
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
void expat_startNamespaceDecl(void *userdata, const XML_Char *prefix, const XML_Char *iri) {
    /* get the data we are working on */
    expat_callback_data callback_data = (expat_callback_data)userdata;

    /* store the new prefix in the list */
    xmlnode_update_decl_list(callback_data->parse_pool, &(callback_data->first_ns), &(callback_data->last_ns), pstrdup(callback_data->parse_pool, prefix), pstrdup(callback_data->parse_pool, iri));
}

/**
 * callback function for the end of the scope of a declared namespace prefix
 *
 * This function will insert the last occurance of the prefix from the list of declared namespaces
 *
 * @param userdata XXX
 * @param prefix prefix that gets undeclared
 */
void expat_endNamespaceDecl(void *userdata, const XML_Char *prefix) {
    /* get the data we are working on */
    expat_callback_data callback_data = (expat_callback_data)userdata;

    /* remove the prefix from the list */
    xmlnode_delete_last_decl(&(callback_data->first_ns), &(callback_data->last_ns), prefix);
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
xmlnode xmlnode_str(char *str, int len) {
    XML_Parser p;
    _expat_callback_data callback_data = { NULL, NULL, NULL, NULL };

    if(NULL == str)
        return NULL;

    callback_data.parse_pool = pool_new();
    p = XML_ParserCreateNS(NULL, XMLNS_SEPARATOR);
    XML_SetUserData(p, &callback_data);
    XML_SetElementHandler(p, expat_startElement, expat_endElement);
    XML_SetCharacterDataHandler(p, expat_charData);
    XML_SetNamespaceDeclHandler(p, expat_startNamespaceDecl, expat_endNamespaceDecl);
    if(!XML_Parse(p, str, len, 1)) {
        /*        jdebug(ZONE,"xmlnode_str_error: %s",(char *)XML_ErrorString(XML_GetErrorCode(p)));*/
        xmlnode_free(callback_data.x);
	callback_data.x = NULL;
    }
    XML_ParserFree(p);
    pool_free(callback_data.parse_pool);
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
xmlnode xmlnode_file(char *file) {
    XML_Parser p;
    _expat_callback_data callback_data = { NULL, NULL, NULL, NULL };
    char buf[BUFSIZ];
    int done, fd, len;

    if(NULL == file)
        return NULL;

    fd = open(file,O_RDONLY);
    if(fd < 0)
        return NULL;

    callback_data.parse_pool = pool_new();
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
            /*            jdebug(ZONE,"xmlnode_file_parseerror: %s",(char *)XML_ErrorString(XML_GetErrorCode(p)));*/
            xmlnode_free(callback_data.x);
	    callback_data.x = NULL;
            done = 1;
        }
    } while (!done);

    XML_ParserFree(p);
    close(fd);
    pool_free(callback_data.parse_pool);
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
char* xmlnode_file_borked(char *file) {
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
            snprintf(err, sizeof(err), "%s at line %d and column %d", XML_ErrorString(XML_GetErrorCode(p)), XML_GetErrorLineNumber(p), XML_GetErrorColumnNumber(p));
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
int xmlnode2file(char *file, xmlnode node)
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
int xmlnode2file_limited(char *file, xmlnode node, size_t sizelimit)
{
    char *doc, *ftmp;
    int fd, i;
    size_t doclen;

    if(file == NULL || node == NULL)
        return -1;

    ftmp = spools(xmlnode_pool(node),file,".t.m.p",xmlnode_pool(node));
    fd = open(ftmp, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if(fd < 0)
        return -1;

    doc = xmlnode2str(node);
    doclen = strlen(doc);

    if (sizelimit > 0 && doclen > sizelimit)
    {
	close(fd);
	return 0;
    }

    i = write(fd,doc,doclen);
    if(i < 0)
        return -1;

    close(fd);

    if(rename(ftmp,file) < 0)
    {
        unlink(ftmp);
        return -1;
    }
    return 1;
}

/**
 * append attributes in the expat format to an existing xmlnode
 *
 * @param owner where to add the attributes
 * @param atts the attributes in expat format (even indexes are the attribute names, odd indexes the values)
 */
void xmlnode_put_expat_attribs(xmlnode owner, const char** atts)
{
    int i = 0;
    if (atts == NULL) return;
    while (atts[i] != '\0')
    {
        xmlnode_put_attrib(owner, atts[i], atts[i+1]);
        i += 2;
    }
}
