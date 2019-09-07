/*
 * Copyrights
 *
 * Portions created by or assigned to Jabber.com, Inc. are
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2019 Matthias Wimmer
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

#ifndef __XSTREAM_HH
#define __XSTREAM_HH

#define XSTREAM_MAXNODE 1000000
#define XSTREAM_MAXDEPTH 100

#define XSTREAM_ROOT 0  /* root element */
#define XSTREAM_NODE 1  /* normal node */
#define XSTREAM_CLOSE 2 /* closed </stream:stream> */
#define XSTREAM_ERR 4   /* parser error */

typedef void (*xstream_onNode)(int type, xmlnode x,
                               void *arg); /* xstream event handler */

typedef struct xstream_struct {
    XML_Parser parser;
    xmlnode node;
    char *cdata;
    int cdata_len;
    pool p;
    xstream_onNode f;
    void *arg;
    int status;
    int depth;

    const char *root_lang; /**< declared language on the root element */

    xmppd::ns_decl_list
        *ns_root; /**< list of declared namespaces for the root element */
    xmppd::ns_decl_list
        *ns_stanza; /**< list of declared namespaces for the current stanza */
} * xstream, _xstream;

xstream xstream_new(pool p, xstream_onNode f,
                    void *arg); /* create a new xstream */
int xstream_eat(xstream xs, char *buff,
                int len); /* parse new data for this xstream, returns last
                             XSTREAM_* status */

/* convience functions */
xmlnode xstream_header(const char *to, const char *from);
char *xstream_header_char(xmlnode x, int stream_type);

/** error cause types for streams, see section 4.7.3 of RFC 3920 */
typedef enum {
    unknown_error_type,    /**< no errror type found, especially legacy stream
                              errors */
    bad_format,            /**< XML cannot be processed */
    bad_namespace_prefix,  /**< unsupported namespace prefix */
    conflict,              /**< new stream has been initiated, that conflicts */
    connection_timeout,    /**< no traffic on the stream for some time */
    host_gone,             /**< hostname is no longer hosted on this server */
    host_unknown,          /**< hostname is not known by this server */
    improper_addressing,   /**< missing to or from attribute */
    internal_server_error, /**< missconfiguration or something like that */
    invalid_from,          /**< from address is not authorzed */
    invalid_id,            /**< invalid stream id */
    invalid_namespace,     /**< wrong namespace for stream or dialback */
    invalid_xml,           /**< invalid XML was found */
    not_authorized,        /**< session not authorized */
    policy_violation,      /**< local service policy violated */
    remote_connection_failed, /**< could not connect to a required remote entity
                                 for auth */
    resource_constraint,      /**< server lacks system resources */
    restricted_xml,           /**< received restricted XML features */
    see_other_host,           /**< redirection to another host */
    system_shutdown,          /**< server is being shut down */
    undefined_condition,      /**< something else ... */
    unsupported_encoding,     /**< stream is coded in an unsupported encoding */
    unsupported_stanza_type,  /**< stanza is not supported */
    unsupported_version,      /**< XMPP version requested is not supported */
    xml_not_well_formed       /**< received XML, that is not well formed */
} streamerr_reason;

/** severity of stream error (well all stream errors are unrecoverable, but we
 * might log them different */
typedef enum {
    normal,        /**< something that is just normal to happen (e.g. connection
                      timeout) */
    configuration, /**< something that seems to be caused by configuration
                      errors (e.g. host gone) */
    feature_lack,  /**< something caused by features not supported by the other
                      end (e.g. unsupported version) */
    unknown,       /**< absolutely no clue */
    error /**< something that shut not happen in any case and seems to be an
             implementation error (e.g. xml_not_well_formed) */
} streamerr_severity;

/** structure that contains information about a stream error */
typedef struct streamerr_struct {
    char *text;              /**< the error message */
    char *lang;              /**< language of the error message */
    streamerr_reason reason; /**< a generic cause type */
    streamerr_severity
        severity; /**< something that admin needs to care about? */
} * streamerr, _streamerr;

void xstream_format_error(std::ostream &out, streamerr errstruct);
streamerr_severity xstream_parse_error(pool p, xmlnode errnode,
                                       streamerr errstruct);

#endif // __XSTREAM_HH
