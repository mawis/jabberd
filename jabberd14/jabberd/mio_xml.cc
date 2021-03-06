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
 * @file mio_xml.cc
 * @brief handling of XML streams on network connections
 *
 * This file implements the functionality used to handle XML streams
 * over network connections. The user can register a callback, that gets
 * an event for the open tag for the root element and for the child elements
 * of the root element (including their child elements).
 */

#include <jabberd.h>

#include <expat.hh>
#include <namespaces.hh>
#include <xmlnode.hh>

#include <fstream>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* defined in mio.c */
extern ios mio__data;

/**
 * internal expat callback for start tags
 *
 * @param m the mio
 * @param name the name of the element
 * @param attribs attributes of the start tag
 */
static void _mio_xstream_startElement(void *_m, const char *name,
                                      const char **attribs) {
    mio m = static_cast<mio>(_m);
    std::string prefix;
    std::string ns_iri;
    std::string local_name;
    std::string qname(name ? name : "");

    // create a new list of declated namespaces if necessary
    if (!m->in_stanza) {
        m->in_stanza = m->in_root ? new xmppd::ns_decl_list(*m->in_root)
                                  : new xmppd::ns_decl_list();
    }

    // get prefix and local name of the element
    std::string::size_type separator_pos = qname.find(XMLNS_SEPARATOR);
    if (separator_pos != std::string::npos) {
        ns_iri = qname.substr(0, separator_pos);
        local_name = qname.substr(separator_pos + 1);
        try {
            // XXX do we need to care about the prefix at all?
            prefix = m->in_stanza->get_nsprefix(ns_iri);
        } catch (std::invalid_argument&) {
        }
    } else {
        // expat could not expand the prefix, it's not declared
        //
        // ... be liberal in what you accept ...
        //
        // XXX do we really want to be?

        // start with a guess
        std::string::size_type colon_pos = qname.find(':');
        if (colon_pos != std::string::npos) {
            prefix = qname.substr(0, colon_pos);
            local_name = qname.substr(colon_pos + 1);
            ns_iri = "http://jabberd.org/ns/clue";

            // some well known prefixes (but tehy would have to be declared!)
            if (prefix == "stream") {
                ns_iri = NS_STREAM;
            } else if (prefix == "db") {
                ns_iri = NS_DIALBACK;
            }
        } else {
            local_name = qname;
            ns_iri = NS_SERVER;
        }
    }

    /* If stacknode is NULL, we are starting a new packet and must
       setup for by pre-allocating some memory */
    if (m->stacknode == NULL) {
        pool p = pool_heap(5 * 1024); /* 5k, typically 1-2k each, plus copy of
                                         self and workspace */
        m->stacknode = xmlnode_new_tag_pool_ns(
            p, local_name.c_str(), prefix == "" ? NULL : prefix.c_str(),
            ns_iri.c_str());
        xmlnode_put_expat_attribs(m->stacknode, attribs, *m->in_stanza);

        /* If the root is 0, this must be the root node.. */
        if (m->flags.root == 0) {
            m->root_lang = pstrdup(m->p, xmlnode_get_lang(m->stacknode));

            /* move the namespace list to where we look for the root namespace
             * list */
            m->in_root = m->in_stanza;
            m->in_stanza = NULL;

            // for the root element: check if NS_SERVER, NS_CLIENT,
            // NS_COMPONENT_ACCEPT, or NS_DIALBACK have been declared => add
            // attribute explicitly
            try {
                std::string prefix = m->in_root->get_nsprefix(NS_SERVER);
                xmlnode_put_attrib_ns(
                    m->stacknode, prefix == "" ? "xmlns" : prefix.c_str(),
                    prefix == "" ? NULL : "xmlns", NS_XMLNS, NS_SERVER);
            } catch (std::invalid_argument&) {
            }
            try {
                std::string prefix = m->in_root->get_nsprefix(NS_CLIENT);
                xmlnode_put_attrib_ns(
                    m->stacknode, prefix == "" ? "xmlns" : prefix.c_str(),
                    prefix == "" ? NULL : "xmlns", NS_XMLNS, NS_CLIENT);
            } catch (std::invalid_argument&) {
            }
            try {
                std::string prefix =
                    m->in_root->get_nsprefix(NS_COMPONENT_ACCEPT);
                xmlnode_put_attrib_ns(m->stacknode,
                                      prefix == "" ? "xmlns" : prefix.c_str(),
                                      prefix == "" ? NULL : "xmlns", NS_XMLNS,
                                      NS_COMPONENT_ACCEPT);
            } catch (std::invalid_argument&) {
            }
            try {
                std::string prefix = m->in_root->get_nsprefix(NS_DIALBACK);
                xmlnode_put_attrib_ns(
                    m->stacknode, prefix == "" ? "xmlns" : prefix.c_str(),
                    prefix == "" ? NULL : "xmlns", NS_XMLNS, NS_DIALBACK);
            } catch (std::invalid_argument&) {
            }

            if (m->cb != NULL)
                (*m->cb)(m, MIO_XML_ROOT, m->cb_arg, m->stacknode, NULL, 0);
            else
                xmlnode_free(m->stacknode);
            m->stacknode = NULL;
            m->flags.root = 1;
        }
    } else {
        m->stacknode = xmlnode_insert_tag_ns(
            m->stacknode, local_name.c_str(),
            prefix == "" ? NULL : prefix.c_str(), ns_iri.c_str());
        xmlnode_put_expat_attribs(m->stacknode, attribs, *m->in_stanza);
    }
}

/**
 * internal expat callback for end tags
 *
 * @param m the mio
 * @param name the name of the element
 */
static void _mio_xstream_endElement(void *_m, const char *name) {
    mio m = static_cast<mio>(_m);

    /* If the stacknode is already NULL, then this closing element
       must be the closing ROOT tag, so notify and exit */
    if (m->stacknode == NULL) {
        /* XXX the following line should not be needed, but we get crashing
         * jabberd14 else, there must be a bug somewhere :(
         *
         * _mio_xstream_endNamespaceDecl() else gets called while processing the
         * <stream:stream/> element, with both arguments (arg and prefix) set to
         * a pointer to the string "db". I have no clue yet, why the arg (which
         * should be a pointer to mio) is replaced by a pointer to the prefix in
         * that case.
         *
         * Not calling _mio_xstream_endNamespaceDecl() helps in that case - as
         * we do not need to delete the namespace from the list anyway, as the
         * mio_st is freed after all that either. (But the call to
         * _mio_xstream_endNamespaceDecl() should happen before mio_st is
         * cleaned.
         */
        XML_SetNamespaceDeclHandler(m->parser, NULL, NULL);
        mio_close(m);
    } else {
        xmlnode parent = xmlnode_get_parent(m->stacknode);
        /* Fire the NODE event if this closing element has no parent */
        if (parent == NULL) {
            // we do not need the list of namespaces for the current stanza
            // anymore
            if (m->in_stanza) {
                delete m->in_stanza;
                m->in_stanza = NULL;
            }

            /* do we have to copy the language of the root element to the stanza
             * root element? */
            if (m->root_lang != NULL && xmlnode_get_lang(m->stacknode) == NULL)
                xmlnode_put_attrib_ns(m->stacknode, "lang", "xml", NS_XML,
                                      m->root_lang);

            if (m->cb != NULL)
                (*m->cb)(m, MIO_XML_NODE, m->cb_arg, m->stacknode, NULL, 0);
            else
                xmlnode_free(m->stacknode);
        }
        m->stacknode = parent;
    }
}

/**
 * internal expat callback for CDATA nodes
 *
 * @param _m the mio
 * @param cdata content of the CDATA node (not zero terminated!)
 * @param len length of the content
 */
void _mio_xstream_CDATA(void *_m, const char *cdata, int len) {
    mio m = static_cast<mio>(_m);

    if (m->stacknode != NULL)
        xmlnode_insert_cdata(m->stacknode, cdata, len);
}

/**
 * callback function for the beginning of a namespace declaration
 *
 * This function will insert a new namespace prefix in the list of declared
 * namespaces
 *
 * @param arg mio the callback is related to
 * @param prefix prefix that gets declared
 * @param iri namespace IRI for this prefix
 */
static void _mio_xstream_startNamespaceDecl(void *arg, const XML_Char *prefix,
                                            const XML_Char *iri) {
    mio m = (mio)arg;

    /* create a new memory pool if necessary, and copy what namespaces we
     * already have on the root element */
    if (!m->in_stanza) {
        m->in_stanza = m->in_root ? new xmppd::ns_decl_list(*m->in_root)
                                  : new xmppd::ns_decl_list();
    }

    /* store the new prefix in the list */
    m->in_stanza->update(prefix ? prefix : "", iri ? iri : "");
}

/**
 * callback function for the end of the scope of a declared namespace prefix
 *
 * This function will insert the last occurance of the prefix from the list of
 * declared namespaces
 *
 * @param arg mio the callback is related to
 * @param prefix prefix that gets undeclared
 */
static void _mio_xstream_endNamespaceDecl(void *arg, const XML_Char *prefix) {
    mio m = (mio)arg;

    /* remove the prefix from the list */
    if (m->in_stanza) {
        m->in_stanza->delete_last(prefix ? prefix : "");
    }
}

/**
 * destructor for a mio xstream, frees allocated memory
 *
 * @param arg the mio of the xstream, that should be closed
 */
void _mio_xstream_cleanup(void *arg) {
    mio m = static_cast<mio>(arg);

    // reset handlers
    if (m->parser) {
        XML_SetElementHandler(m->parser, NULL, NULL);
        XML_SetCharacterDataHandler(m->parser, NULL);
        XML_SetNamespaceDeclHandler(m->parser, NULL, NULL);
    }

    xmlnode_free(m->stacknode);
    m->stacknode = NULL;

    if (m->parser)
        XML_ParserFree(m->parser);
    m->parser = NULL;

    if (m->in_root) {
        delete m->in_root;
        m->in_root = NULL;
    }
    if (m->in_stanza) {
        delete m->in_stanza;
        m->in_stanza = NULL;
    }
    if (m->out_ns) {
        delete m->out_ns;
        m->out_ns = NULL;
    }
}

/**
 * init an xstream for a mio object
 *
 * (allocates a XML parser instance)
 *
 * @param m which mio object should be prepared for usage as an XML stream
 */
void _mio_xstream_init(mio m) {
    if (m != NULL) {
        /* Initialize the parser */
        m->parser = XML_ParserCreateNS(NULL, XMLNS_SEPARATOR);
        XML_SetUserData(m->parser, m);
        XML_SetElementHandler(m->parser, _mio_xstream_startElement,
                              _mio_xstream_endElement);
        XML_SetCharacterDataHandler(m->parser, _mio_xstream_CDATA);
        XML_SetNamespaceDeclHandler(m->parser, _mio_xstream_startNamespaceDecl,
                                    _mio_xstream_endNamespaceDecl);
        /* Setup a cleanup routine to release the parser when everything is done
         */
        pool_cleanup(m->p, _mio_xstream_cleanup, (void *)m);
    }
}

/**
 * receiving an XML document on a network socket
 *
 * This parser implements an XML parser reading on a network socket. Stanzas
 * (second level XML document elements) are passed to the application callback
 * function, that registered with this mio object
 *
 * @param m the mio where data has been read
 * @param vbuf the buffer containing the read data
 * @param bufsz the number of bytes, that have been read
 */
void _mio_xml_parser(mio m, const void *vbuf, size_t bufsz) {
    char *nul, *buf = (char *)vbuf;

    /* check if the stream has to be resetted (after STARTTLS) */
    if (m->flags.reset_stream) {
        _mio_xstream_cleanup(m);
        m->flags.root = 0; /* read root element again */
        m->flags.reset_stream = 0;
    }

    /* init the parser if this is the first read call */
    if (m->parser == NULL) {
        _mio_xstream_init(m);

        /* XXX pretty big hack here, if the initial read contained a nul, assume
         * nul-packet-terminating format stream */
        if ((nul = strchr(buf, '\0')) != NULL && (size_t)(nul - buf) < bufsz) {
            m->type = type_NUL;
            nul[-2] =
                ' '; /* assume it's .../>0 and make the stream open again */
        }

        // Check for HTTP requests, extract first line for that reason
        std::string buffer_data(buf, bufsz);
        std::istringstream buffer_stream(buffer_data);
        std::string first_line;
        std::getline(buffer_stream, first_line);

        // PUT/POST requests are a legacy hack to bypass some HTTP proxies
        // Note: Most HTTP proxies do not forward these PUT/POST requests
        // of Jabber. Using proxy CONNECT with a jabberd listening on port
        // 443 seems to work better.
        if (first_line.substr(0, 1) == "P") {
            m->type = type_HTTP;
        }

        // GET requests: first check if we do serve our own file, else we might
        // have been configured to forward the request to some URI.
        if (first_line.substr(0, 4) == "GET ") {
            // extract path and protocol
            std::istringstream first_line_stream(first_line.substr(4));
            std::string request_path;
            std::string request_protocol;
            first_line_stream >> request_path >> request_protocol;
            log_debug2(ZONE, LOGT_IO, "handling HTTP-GET path=%s, protocol=%s",
                       request_path.c_str(), request_protocol.c_str());

            // internal mini webserver enabled?
            if (mio__data->webserver_path) {
                char request_path_copy[1024] = "";
                snprintf(request_path_copy, sizeof(request_path_copy), "%s",
                         request_path.c_str());
                request_path_copy[sizeof(request_path_copy) - 1] =
                    0; // make sure the string is terminated
                std::string request_basename = ::basename(request_path_copy);
                if (request_basename == "/" || request_basename == "") {
                    request_basename = "index.html";
                }
                log_debug2(ZONE, LOGT_IO, "GET request processing for file %s",
                           request_basename.c_str());

                // check that the file is not a directory
                std::string filename = std::string(mio__data->webserver_path) +
                                       "/" + request_basename;
                struct stat stat_buf;
                int stat_ret = ::stat(filename.c_str(), &stat_buf);
                if (stat_ret == 0 && S_ISREG(stat_buf.st_mode)) {
                    // try to open file
                    std::ifstream file(filename.c_str(), std::ifstream::binary);
                    if (file.is_open()) {
                        // get the file size
                        file.seekg(0, std::ios::end);
                        std::streampos file_size = file.tellg();
                        file.seekg(0, std::ios::beg);

                        if (file_size >= 1024 * 1024) {
                            log_error(NULL,
                                      "mini-webserver tried to return %s "
                                      "(size: %i B) which is bigger than 1 "
                                      "MiB. Not able to handle that big files",
                                      filename.c_str(),
                                      static_cast<int>(file_size));

                            std::string message("Request entity too large\r\n");

                            std::ostringstream http_result;
                            http_result
                                << (request_protocol == "" ||
                                            request_protocol == "HTTP/1.0"
                                        ? "HTTP/1.0"
                                        : "HTTP/1.1")
                                << " 413 Request entity too large\r\n";
                            http_result
                                << "Server: " PACKAGE " " VERSION "\r\n";
                            http_result << "Connection: close\r\n";
                            http_result
                                << "Content-Length: " << message.length()
                                << "\r\n";
                            http_result << "Content-Type: text/plain; "
                                           "charset=utf-8\r\n";
                            http_result << "\r\n";
                            http_result << message;

                            mio_write(m, NULL, http_result.str().c_str(),
                                      http_result.str().length());
                            mio_close(m);
                        } else {
                            if (file_size >= 1024 * 100) {
                                log_warn(NULL,
                                         "Warning: mini-webserver is returning "
                                         "%s (size: %i B). You should not use "
                                         "jabberd to handle big files!",
                                         filename.c_str(),
                                         static_cast<int>(file_size));
                            }

                            char *result_buffer = new char[file_size];

                            file.read(result_buffer, file_size);

                            std::ostringstream http_result;
                            http_result
                                << (request_protocol == "" ||
                                            request_protocol == "HTTP/1.0"
                                        ? "HTTP/1.0"
                                        : "HTTP/1.1")
                                << " 200 OK\r\n";
                            http_result
                                << "Server: " PACKAGE " " VERSION "\r\n";
                            http_result << "Connection: close\r\n";
                            http_result << "Content-Length: " << file_size
                                        << "\r\n";
                            http_result << "Content-Type: text/html\r\n";
                            http_result << "\r\n";
                            http_result
                                << std::string(result_buffer, file_size);

                            delete[] result_buffer;

                            mio_write(m, NULL, http_result.str().c_str(),
                                      http_result.str().length());
                            mio_close(m);
                        }

                        // close the file
                        file.close();

                        // we handle the request
                        return;
                    }
                }
            }

            // no document returned, send a bounce
            std::ostringstream http_result;
            http_result << (request_protocol == "" ||
                                    request_protocol == "HTTP/1.0"
                                ? "HTTP/1.0"
                                : "HTTP/1.1")
                        << " 301 Moved permanently\r\n";
            http_result << "Server: " PACKAGE " " VERSION "\r\n";
            http_result << "Connection: close\r\n";
            // bounce to a configured host?
            if (mio__data->bounce_uri) {
                http_result << "Location: " << mio__data->bounce_uri << "\r\n";
            } else {
                http_result << "Location: " HTTP_BOUNCE_URI "\r\n";
            }
            http_result << "\r\n";

            mio_write(m, NULL, http_result.str().c_str(),
                      http_result.str().length());
            mio_close(m);

            // we handled the request now
            return;
        }

        // check for Flash policy requests
        if (first_line.substr(0, 20) == "<policy-file-request") {
            // reset type to type_NORMAL, else mio will add a "/>" to the data
            // that is sent back
            m->type = type_NORMAL;

            // is there a configured flash policy?
            if (mio__data->flash_policy) {
                struct stat stat_buf;
                int stat_ret = ::stat(mio__data->flash_policy, &stat_buf);
                if (stat_ret == 0 && S_ISREG(stat_buf.st_mode)) {
                    // try to open file
                    std::ifstream file(mio__data->flash_policy,
                                       std::ifstream::binary);
                    if (file.is_open()) {
                        // get the file size
                        file.seekg(0, std::ios::end);
                        std::streampos file_size = file.tellg();
                        file.seekg(0, std::ios::beg);

                        if (file_size < 1024 * 1024) {
                            char *result_buffer = new char[file_size];
                            file.read(result_buffer, file_size);
                            std::string result_string(result_buffer, file_size);
                            mio_write(m, NULL, result_string.c_str(),
                                      result_string.length() + 1);
                            delete[] result_buffer;

                            mio_close(m);
                            file.close();
                            return;
                        }

                        log_warn(NULL, "Flash policy file is too big for being "
                                       "returned to the flash client.");
                        file.close();
                    }
                }
            }

            // no configured flash policy, or policy too big. Send default
            std::string default_policy(
                "<?xml version='1.0'?>\n<!DOCTYPE cross-domain-policy SYSTEM "
                "\"/xml/dtds/cross-domain-policy.dtd\">\n<cross-domain-policy/"
                ">\n");
            log_notice(NULL, "Received Flash policy-file-request, but non is "
                             "configured. Returning (empty) default policy.");
            mio_write(m, NULL, default_policy.c_str(),
                      default_policy.length() +
                          1); // length()+1 because we want to
                              // send the NULL byte as well
            mio_close(m);
            return;
        }
    }

    /* XXX more http hack to catch the end of the headers */
    if (m->type == type_HTTP) {
        if ((nul = strstr(buf, "\r\n\r\n")) == NULL)
            return;
        nul += 4;
        bufsz = bufsz - (nul - buf);
        buf = nul;
        mio_write(
            m, NULL,
            "HTTP/1.0 200 Ok\r\nServer: jabber/xmlstream-hack-0.1\r\nExpires: "
            "Fri, 10 Oct 1997 10:10:10 GMT\r\nPragma: "
            "no-cache\r\nCache-control: private\r\nConnection: close\r\n\r\n",
            -1);
        m->type = type_NORMAL;
    }

    /* XXX more nul-term hack to ditch the nul's whenever */
    if (m->type == type_NUL)
        while ((nul = strchr(buf, '\0')) != NULL &&
               (size_t)(nul - buf) < bufsz) {
            memmove(nul, nul + 1, strlen(nul + 1));
            bufsz--;
        }

    if (XML_Parse(m->parser, buf, bufsz, 0) == 0) {
        log_debug2(ZONE, LOGT_XML, "[%s] XML Parsing Error: %s", ZONE,
                   XML_ErrorString(XML_GetErrorCode(m->parser)));
        if (m->cb != NULL) {
            (*m->cb)(m, MIO_ERROR, m->cb_arg, NULL, NULL, 0);
            mio_write(m, NULL,
                      "<stream:error><invalid-xml "
                      "xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text "
                      "xmlns='urn:ietf:params:xml:ns:xmpp-streams' "
                      "xml:lang='en'>Invalid XML</text></stream:error>",
                      -1);
            mio_close(m);
        }
    }
}

/**
 * reset a stream (restart it)
 *
 * @param m the stream to reset
 */
void mio_xml_reset(mio m) {
    /* flag that the stream has to be resetted, we cannot reset it
     * here, as we might have been called from within expat and the
     * return would fail then */
    m->flags.reset_stream = 1;
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
    int result = 0;

    /* flush the write queue */
    if (_mio_write_dump(m) != 0) {
        log_debug2(ZONE, LOGT_IO,
                   "Failed to flush queue before switching to TLS");
        return 1;
    }

    /* start the TLS layer on the connection */
    result = mio_ssl_starttls(m, originator, identity);
    if (result != 0) {
        log_debug2(
            ZONE, LOGT_IO,
            "mio_ssl_starttls() failed ... so mio_xml_starttls() fails ...");
        return result;
    }

    mio_xml_reset(m);

    return 0;
}
