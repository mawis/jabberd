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
 * @file mio_xml.c
 * @brief handling of XML streams on network connections
 *
 * This file implements the functionality used to handle XML streams
 * over network connections. The user can register a callback, that gets
 * an event for the open tag for the root element and for the child elements
 * of the root element (including their child elements).
 */

#include <jabberd.h>

/* defined in mio.c */
extern char *mio__bounce_uri;

/**
 * internal expat callback for start tags
 *
 * @param m the mio
 * @param name the name of the element
 * @param attribs attributes of the start tag
 */
void _mio_xstream_startElement(mio m, const char* name, const char** attribs)
{
    /* If stacknode is NULL, we are starting a new packet and must
       setup for by pre-allocating some memory */
    if (m->stacknode == NULL) {
	pool p = pool_heap(5 * 1024); /* 5k, typically 1-2k each, plus copy of self and workspace */
	m->stacknode = xmlnode_new_tag_pool(p, name);
	xmlnode_put_expat_attribs(m->stacknode, attribs);

	/* If the root is 0, this must be the root node.. */
	if (m->root == 0) {
	    if(m->cb != NULL)
		(*(mio_xml_cb)m->cb)(m, MIO_XML_ROOT, m->cb_arg, m->stacknode);
	    else
		xmlnode_free(m->stacknode);
	    m->stacknode = NULL;
	    m->root = 1;
	}
    } else {
	m->stacknode = xmlnode_insert_tag(m->stacknode, name);
	xmlnode_put_expat_attribs(m->stacknode, attribs);
    }
}

/**
 * internal expat callback for end tags
 *
 * @param m the mio
 * @param name the name of the element
 */
void _mio_xstream_endElement(mio m, const char* name)
{
    /* If the stacknode is already NULL, then this closing element
       must be the closing ROOT tag, so notify and exit */
    if (m->stacknode == NULL)
    {
        mio_close(m);
    }
    else
    {
	xmlnode parent = xmlnode_get_parent(m->stacknode);
	/* Fire the NODE event if this closing element has no parent */
	if (parent == NULL) {
	    if(m->cb != NULL)
		(*(mio_xml_cb)m->cb)(m, MIO_XML_NODE, m->cb_arg, m->stacknode);
	    else
		xmlnode_free(m->stacknode);
	}
	m->stacknode = parent;
    }
}

/**
 * internal expat callback for CDATA nodes
 *
 * @param m the mio
 * @param cdata content of the CDATA node (not zero terminated!)
 * @param len length of the content
 */
void _mio_xstream_CDATA(mio m, const char* cdata, int len)
{
    if (m->stacknode != NULL)
	    xmlnode_insert_cdata(m->stacknode, cdata, len);
}

/**
 * destructor for a mio xstream, frees allocated memory
 *
 * @param arg the mio of the xstream, that should be closed
 */
void _mio_xstream_cleanup(void* arg)
{
    mio m = (void*)arg;

    xmlnode_free(m->stacknode);
    m->stacknode = NULL;
    if (m->parser)
	XML_ParserFree(m->parser);
    m->parser = NULL;
}

/**
 * init an xstream for a mio object
 *
 * (allocates a XML parser instance)
 *
 * @param m which mio object should be prepared for usage as an XML stream
 */
void _mio_xstream_init(mio m)
{
    if (m != NULL)
    {
	    /* Initialize the parser */
	    m->parser = XML_ParserCreate(NULL);
	    XML_SetUserData(m->parser, m);
	    XML_SetElementHandler(m->parser, (void*)_mio_xstream_startElement, (void*)_mio_xstream_endElement);
	    XML_SetCharacterDataHandler(m->parser, (void*)_mio_xstream_CDATA);
	    /* Setup a cleanup routine to release the parser when everything is done */
	    pool_cleanup(m->p, _mio_xstream_cleanup, (void*)m);
    }
}

/* this function is called when a socket reads data */
void _mio_xml_parser(mio m, const void *vbuf, size_t bufsz)
{
    char *nul, *buf = (char*)vbuf;

    /* check if the stream has to be resetted (after STARTTLS) */
    if (m->reset_stream > 0) {
	_mio_xstream_cleanup(m);
	m->root = 0;	/* read root element again */
	m->reset_stream = 0;
    }

    /* init the parser if this is the first read call */
    if(m->parser == NULL)
    {
        _mio_xstream_init(m);
        /* XXX pretty big hack here, if the initial read contained a nul, assume nul-packet-terminating format stream */
        if((nul = strchr(buf,'\0')) != NULL && (nul - buf) < bufsz)
        {
            m->type = type_NUL;
            nul[-2] = ' '; /* assume it's .../>0 and make the stream open again */
        }
        /* XXX another big hack/experiment, for bypassing dumb proxies */
        if(*buf == 'P')
            m->type = type_HTTP;

	/* Bounce HTTP-GET-Requests to the configured host */
	if(*buf == 'G' && mio__bounce_uri != NULL) {
	    mio_write(m, NULL, "HTTP/1.1 301 Moved permanently\r\nServer: " PACKAGE " " VERSION "\r\nConnection: close\r\nLocation: ", -1);
	    mio_write(m, NULL, mio__bounce_uri, -1);
	    mio_write(m, NULL, "\r\n\r\n", -1);
	    mio_close(m);
	    return;
	}
    }

    /* XXX more http hack to catch the end of the headers */
    if(m->type == type_HTTP)
    {
        if((nul = strstr(buf,"\r\n\r\n")) == NULL)
            return;
        nul += 4;
        bufsz = bufsz - (nul - buf);
        buf = nul;
        mio_write(m,NULL,"HTTP/1.0 200 Ok\r\nServer: jabber/xmlstream-hack-0.1\r\nExpires: Fri, 10 Oct 1997 10:10:10 GMT\r\nPragma: no-cache\r\nCache-control: private\r\nConnection: close\r\n\r\n",-1);
        m->type = type_NORMAL;
    }

    /* XXX more nul-term hack to ditch the nul's whenever */
    if(m->type == type_NUL)
        while((nul = strchr(buf,'\0')) != NULL && (nul - buf) < bufsz)
        {
            memmove(nul,nul+1,strlen(nul+1));
            bufsz--;
        }

    if(XML_Parse(m->parser, buf, bufsz, 0) == 0)
        if(m->cb != NULL)
        {
            log_debug2(ZONE, LOGT_XML, "[%s] XML Parsing Error: %s", ZONE, XML_ErrorString(XML_GetErrorCode(m->parser)));
            (*(mio_std_cb)m->cb)(m, MIO_ERROR, m->cb_arg);
            mio_write(m, NULL, "<stream:error><invalid-xml xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Invalid XML</text></stream:error>", -1);
            mio_close(m);
        }
}

/**
 * restart a stream, starting the use of a TLS layer
 *
 * @param m the connection
 * @param originator 1 if we are the originator, 0 else
 * @param identity identity to use for selecting the certificate
 * @return 0 on success, non-zero on failure
 */
int mio_xml_starttls(mio m, int originator, const char *identity) {
#ifdef HAVE_SSL
    int result = 0;
    int waited = 0;

    /* flush the write queue */
    if (_mio_write_dump(m) != 0) {
	log_debug2(ZONE, LOGT_IO, "Failed to flush queue before switching to TLS");
	return 1;
    }

    /* start the TLS layer on the connection */
    result = mio_ssl_starttls(m, originator, identity);
    if (result != 0) {
	log_debug2(ZONE, LOGT_IO, "mio_ssl_starttls() failed ... so mio_xml_starttls() fails ...");
	return result;
    }

    /* flag that the stream has to be resetted, we cannot reset it
     * here, as we might have been called from within expat and the
     * return would fail then */
    m->reset_stream = 1;

    return 0;
#else /* no SSL enabled */
    return 1;
#endif /* HAVE_SSL */
}
