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
void expat_startElement(void* userdata, const char* name, const char** atts)
{
    /* get the xmlnode pointed to by the userdata */
    xmlnode *x = userdata;
    xmlnode current = *x;

    if (current == NULL)
    {
        /* allocate a base node */
        current = xmlnode_new_tag(name);
        xmlnode_put_expat_attribs(current, atts);
        *x = current;
    }
    else
    {
        *x = xmlnode_insert_tag(current, name);
        xmlnode_put_expat_attribs(*x, atts);
    }
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
void expat_endElement(void* userdata, const char* name)
{
    xmlnode *x = userdata;
    xmlnode current = *x;

    /*
    current->complete = 1;
    */
    current = xmlnode_get_parent(current);

    /* if it's NULL we've hit the top folks, otherwise back up a level */
    if(current != NULL)
        *x = current;
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
void expat_charData(void* userdata, const char* s, int len)
{
    xmlnode *x = userdata;
    xmlnode current = *x;

    xmlnode_insert_cdata(current, s, len);
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
xmlnode xmlnode_str(char *str, int len)
{
    XML_Parser p;
    xmlnode *x, node; /* pointer to an xmlnode */

    if(NULL == str)
        return NULL;

    x = malloc(sizeof(void *));

    *x = NULL; /* pointer to NULL */
    p = XML_ParserCreate(NULL);
    XML_SetUserData(p, x);
    XML_SetElementHandler(p, expat_startElement, expat_endElement);
    XML_SetCharacterDataHandler(p, expat_charData);
    if(!XML_Parse(p, str, len, 1))
    {
        /*        jdebug(ZONE,"xmlnode_str_error: %s",(char *)XML_ErrorString(XML_GetErrorCode(p)));*/
        xmlnode_free(*x);
        *x = NULL;
    }
    node = *x;
    free(x);
    XML_ParserFree(p);
    return node; /* return the xmlnode x points to */
}

/**
 * create an xmlnode instance (possibly including other xmlnode instances) by parsing a file
 *
 * This function will parse a file containing an XML document and create an xmlnode graph
 *
 * @param file the filename
 * @return the graph of xmlnodes that represent the parsed document, NULL on failure
 */
xmlnode xmlnode_file(char *file)
{
    XML_Parser p;
    xmlnode *x, node; /* pointer to an xmlnode */
    char buf[BUFSIZ];
    int done, fd, len;

    if(NULL == file)
        return NULL;

    fd = open(file,O_RDONLY);
    if(fd < 0)
        return NULL;

    x = malloc(sizeof(void *));

    *x = NULL; /* pointer to NULL */
    p = XML_ParserCreate(NULL);
    XML_SetUserData(p, x);
    XML_SetElementHandler(p, expat_startElement, expat_endElement);
    XML_SetCharacterDataHandler(p, expat_charData);
    do{
        len = read(fd, buf, BUFSIZ);
        done = len < BUFSIZ;
        if(!XML_Parse(p, buf, len, done))
        {
            /*            jdebug(ZONE,"xmlnode_file_parseerror: %s",(char *)XML_ErrorString(XML_GetErrorCode(p)));*/
            xmlnode_free(*x);
            *x = NULL;
            done = 1;
        }
    }while(!done);

    node = *x;
    XML_ParserFree(p);
    free(x);
    close(fd);
    return node; /* return the xmlnode x points to */
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

    p = XML_ParserCreate(NULL);
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
