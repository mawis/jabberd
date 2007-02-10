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
 * --------------------------------------------------------------------------*/

/**
 * @file mio_tls.c
 * @brief MIO read/write functions to read/write on TLS encrypted sockets and handling for TLS in general (using the GNU TLS implementation)
 */

#include "jabberd.h"
#ifdef HAVE_GNUTLS
#include <libtasn1.h>
#include <map>
#include <string>
#include <sstream>

extern const ASN1_ARRAY_TYPE subjectAltName_asn1_tab[];

/**
 * the credentials used by the server
 *
 * key is the virtual domain the credentials are used for ("*" for the default)
 * value the credentials to use
 */
std::map<std::string, gnutls_certificate_credentials_t> mio_tls_credentials;

/**
 * tree of ASN1 structures
 */
ASN1_TYPE mio_tls_asn1_tree = ASN1_TYPE_EMPTY;

/**
 * initialize the mio SSL/TLS module using the GNU TLS library
 *
 * @param x xmlnode containing the configuration information (the io/tls element)
 */
void mio_ssl_init(xmlnode x) {
    xmlnode cur = NULL;
    int ret = 0;
    static gnutls_dh_params_t mio_tls_dh_params;
    xht namespaces = NULL;
    gnutls_certificate_credentials_t mio_tls_x509_cred;

    log_debug2(ZONE, LOGT_IO, "MIO TLS init (GNU TLS)");

    namespaces = xhash_new(3);
    xhash_put(namespaces, "", const_cast<char*>(NS_JABBERD_CONFIGFILE));

    /* initialize the GNU TLS library */
    ret = gnutls_global_init();
    if (ret != 0) {
	log_error(ZONE, "Error initializing GNU TLS library: %s", gnutls_strerror(ret));
	/* XXX what to do now? */
    }

    /* load asn1 tree to be used by libtasn1 */
    ret = asn1_array2tree(subjectAltName_asn1_tab, &mio_tls_asn1_tree, NULL);
    if (ret != ASN1_SUCCESS) {
	log_error(ZONE, "Error preparing the libtasn1 library: %s", libtasn1_strerror(ret));
	/* XXX what to do now? */

	/* XXX we have to delete the structure on shutdown using asn1_delete_structure(&mio_tls_asn1_tree) */
    }

    /* find the default CA certificates file */
    std::string default_cacertfile;
    for (cur = xmlnode_get_firstchild(x); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	if (cur->type != NTYPE_TAG) {
	    continue;
	}

	if (j_strcmp(xmlnode_get_localname(cur), "cacertfile") == 0 && j_strcmp(xmlnode_get_namespace(cur), NS_JABBERD_CONFIGFILE) == 0) {
	    char const* const cacertfile_data = xmlnode_get_data(cur);

	    if (cacertfile_data != NULL) {
		default_cacertfile = cacertfile_data;
	    }
	}
    }

    /* create DH parameters */
    ret = gnutls_dh_params_init(&mio_tls_dh_params);
    if (ret < 0) {
	log_error(ZONE, "Error initializing DH params: %s", gnutls_strerror(ret));
    }
    ret = gnutls_dh_params_generate2(mio_tls_dh_params, 1024);
    if (ret < 0) {
	log_error(ZONE, "Error generating DH params: %s", gnutls_strerror(ret));
    }

    /* load certificates and such ... */
    ret = gnutls_certificate_allocate_credentials (&mio_tls_x509_cred);
    mio_tls_credentials["*"] = mio_tls_x509_cred;
    if (ret != 0) {
	log_error(ZONE, "Error allocating GNU TLS credentials: %s", gnutls_strerror(ret));
	/* XXX what to do now? */
    }

    /* load the certificates */
    for (cur = xmlnode_get_firstchild(x); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	if (cur->type != NTYPE_TAG) {
	    continue;
	}

	/* it's a key */
	if (j_strcmp(xmlnode_get_localname(cur), "key") == 0 && j_strcmp(xmlnode_get_namespace(cur), NS_JABBERD_CONFIGFILE) == 0) {
	    char *file_to_use = xmlnode_get_data(cur);
	    char *key_type = xmlnode_get_attrib_ns(cur, "type", NULL);
	    char *id = xmlnode_get_attrib_ns(cur, "id", NULL);
	    char *private_key_file = xmlnode_get_attrib_ns(cur, "private-key", NULL);
	    char *no_ssl_v2 = xmlnode_get_attrib_ns(cur, "no-ssl-v2", NULL);
	    char *no_ssl_v3 = xmlnode_get_attrib_ns(cur, "no-ssl-v3", NULL);
	    char *no_tls_v1 = xmlnode_get_attrib_ns(cur, "no-tls-v1", NULL);
	    char *ciphers = xmlnode_get_attrib_ns(cur, "ciphers", NULL);
	    gnutls_x509_crt_fmt_t certificate_type = GNUTLS_X509_FMT_PEM;

	    /* no id attribute? first try ip instead, else default key */
	    if (id == NULL) {
		id = xmlnode_get_attrib_ns(cur, "ip", NULL);
		if (id == NULL) {
		    id = "*";
		}
	    }

	    /* no public key file? */
	    if (file_to_use == NULL) {
		log_notice(id, "Cannot load X.509 certificate: no file specified.");
		continue;
	    }

	    /* PEM or DER format? */
	    if (j_strcmp(xmlnode_get_attrib_ns(cur, "type", NULL), "der") == 0) {
		certificate_type = GNUTLS_X509_FMT_DER;
	    }

	    /* check old attributes not supported anymore */
	    if (no_ssl_v2 != NULL || no_ssl_v3 != NULL || no_tls_v1 != NULL || ciphers != NULL) {
		log_notice(id, "Warning: ignoring a attribute when loading X.509 certificate. Not supported anymore are: no-ssl-v2, no-ssl-v3, no-tls-v1 and ciphers");
	    }

	    /* no special private key file? use the same as the public key file */
	    if (private_key_file == NULL) {
		private_key_file = file_to_use;
	    }

	    /* load the keys */
	    gnutls_certificate_credentials_t current_credentials = NULL;
	    ret = gnutls_certificate_allocate_credentials (&current_credentials);
	    if (ret < 0) {
		log_error(id, "Error initializing credentials: %s", gnutls_strerror(ret));
		continue;
	    }
	    ret = gnutls_certificate_set_x509_key_file(current_credentials, file_to_use, private_key_file, certificate_type);
	    if (ret < 0) {
		log_error(id, "Error loading key file cert=%s/priv=%s: %s", file_to_use, private_key_file, gnutls_strerror(ret));
		gnutls_certificate_free_credentials(current_credentials);
		continue;
	    }

	    /* load CA certificates */
	    if (default_cacertfile != "") {
		ret = gnutls_certificate_set_x509_trust_file(current_credentials, default_cacertfile.c_str(), GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
		    log_error(id, "Error loading CA certificates: %s", gnutls_strerror(ret));
		}
	    } else {
		log_warn(id, "Not loading CA certificates for %s", id);
	    }

	    /* set the DH params for this certificate */
	    gnutls_certificate_set_dh_params(current_credentials, mio_tls_dh_params);

	    /* store the loaded certificate */
	    mio_tls_credentials[id] = current_credentials;
	}
    }

    xhash_free(namespaces);
    namespaces = NULL;
}

void _mio_ssl_cleanup(void *arg) {
    gnutls_session_t session = (gnutls_session_t)arg;

    log_debug2(ZONE, LOGT_IO, "GNU TLS session cleanup for %X", session);
    gnutls_deinit(session);
}

/**
 * read data from a socket, that is TLS protected
 *
 * The m->flags.recall_read_when_readable and m->flags.recall_read_when_writeable is updated by this function.
 *
 * @param m the ::mio where data might be available
 * @param buf where to write the written data to
 * @param count how many bytes should be read at most
 * @return 0 < ret < count: ret bytes read and no more bytes to read; ret = count: ret bytes read, possibly more bytes to read; ret = 0: currently nothing to read; ret < 0: non-recoverable error or connection closed
 */
ssize_t _mio_ssl_read(mio m, void *buf, size_t count) {
    int read_return = 0;

    /* sanity checks */
    if (count <= 0 || buf == NULL || m == NULL) {
	return count == 0 ? 0 : -1;
    }

    log_debug2(ZONE, LOGT_IO, "Trying to read up to %i B from socket %i using GnuTLS", count, m->fd);

    /* reset flags */
    m->flags.recall_read_when_readable = 0;
    m->flags.recall_read_when_writeable = 0;

    /* trying to read */
    read_return = gnutls_record_recv(static_cast<gnutls_session_t>(m->ssl), (char*)buf, count);

    if (read_return > 0) {
	log_debug2(ZONE, LOGT_IO, "Read %i B on socket %i", read_return, m->fd);
	return read_return;
    }
    if (read_return == GNUTLS_E_INTERRUPTED || read_return == GNUTLS_E_AGAIN) {
	if (gnutls_record_get_direction(static_cast<gnutls_session_t>(m->ssl)) == 0) {
	    m->flags.recall_read_when_readable = 1;
	} else {
	    m->flags.recall_read_when_writeable = 1;
	}
	return 0;
    }

    log_debug2(ZONE, LOGT_IO, "Error case after gnutls_record_recv(): %s", gnutls_strerror(read_return));

    return -1;
}

/**
 * write data to a socket, that is TLS protected
 *
 * The m->flags.recall_write_when_readable and m->flags.recall_write_when_writeable is updated by this function.
 *
 * @param m the ::mio where writing is possible
 * @param buf data that should be written
 * @param count how many bytes should be written at most
 * @param ret > 0: ret bytes written; ret == 0: no bytes could be written; ret < 0: non-recoverable error or connection closed
 */
ssize_t _mio_ssl_write(mio m, const void *buf, size_t count) {
    int write_return = 0;

    /* sanity checks */
    if (count <= 0 || buf == NULL || m == NULL) {
	return count == 0 ? 0 : -1;
    }

    log_debug2(ZONE, LOGT_IO, "Trying to write up to %i B to socket %i using GnuTLS", count, m->fd);

    /* reset flags */
    m->flags.recall_write_when_readable = 0;
    m->flags.recall_write_when_writeable = 0;

    /* trying to write data */
    write_return = gnutls_record_send(static_cast<gnutls_session_t>(m->ssl), buf, count);

    if (write_return > 0) {
	log_debug2(ZONE, LOGT_IO, "Wrote %i B on socket %i", write_return, m->fd);
	return write_return;
    }
    if (write_return == GNUTLS_E_INTERRUPTED || write_return == GNUTLS_E_AGAIN) {
	if (gnutls_record_get_direction(static_cast<gnutls_session_t>(m->ssl)) == 0) {
	    m->flags.recall_write_when_readable = 1;
	} else {
	    m->flags.recall_write_when_writeable = 1;
	}
	return 0;
    }

    log_debug2(ZONE, LOGT_IO, "Error case after gnutls_record_send(): %s", gnutls_strerror(write_return));

    return -1;
}

/**
 * continue a TLS handshake (as server side) when new data is available or data can be written now
 *
 * @param m the mio of the socket
 * @return -1 on error, 0 if handshake did not complete yet, 1 on success
 */
int _mio_tls_cont_handshake_server(mio m) {
    int ret = 0;

    /* we are recalled, if neccessary we set the flags again */
    m->flags.recall_handshake_when_readable = 0;
    m->flags.recall_handshake_when_writeable = 0;

    /* continue the handshake */
    ret = gnutls_handshake(static_cast<gnutls_session_t>(m->ssl));
    if (ret >= 0) {
	/* reset the handler for handshake */
	m->mh->handshake = NULL;
	log_debug2(ZONE, LOGT_IO, "TLS handshake finished for fd #%i", m->fd);
	return 1;
    } else if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
	if (gnutls_record_get_direction(static_cast<gnutls_session_t>(m->ssl)) == 0) {
	    log_debug2(ZONE, LOGT_IO, "TLS layer needs to read data to complete handshake (fd #%i)", m->fd);
	    m->flags.recall_handshake_when_readable = 1;
	} else {
	    log_debug2(ZONE, LOGT_IO, "TLS layer needs to write data to complete handshake (fd #%i)", m->fd);
	    m->flags.recall_handshake_when_writeable = 1;
	}
	return 0;
    } else {
	log_debug2(ZONE, LOGT_IO, "TLS handshake failed for fd #%i: %s", m->fd, gnutls_strerror(ret));
	return -1;
    }
}

/**
 * accepted a new incoming connection, where we have to start the TLS layer without a STARTTLS command, e.g. on port 5223
 *
 * @param m the mio of the listening socket
 * @return -1 on error, 0 if the handshake has not yet finished, 1 on success
 */
int _mio_ssl_accepted(mio m) {
    return mio_ssl_starttls(m, 0, m->our_ip) == 0 ? 1 : -1;
}

/**
 * check if a connection is encrypted
 *
 * @param m the connection
 * @return 0 if the connection is unprotected, 1 if the connection is integrity protected, >1 if the connection is encrypted
 */
int mio_is_encrypted(mio m) {
    return m->ssl == NULL ? 0 : 8*gnutls_cipher_get_key_size(gnutls_cipher_get(static_cast<gnutls_session_t>(m->ssl)));
}

/**
 * check if it would be possible to start TLS on a connection
 *
 * @param m the connection
 * @param identity our own identity (check if certificate is present)
 * @return 0 if it is impossible, 1 if it is possible
 */
int mio_ssl_starttls_possible(mio m, const char* identity) {
    /* if the connection is already TLS protected, we cannot start a second TLS layer */
    if (m->ssl != NULL) {
	return 0;
    }

    /* check if we have a certificate for this domain */
    if (identity != NULL && mio_tls_credentials.find(identity) != mio_tls_credentials.end()) {
	return 1;
    }

    /* or there might be a default certificate */
    if (mio_tls_credentials.find("*") != mio_tls_credentials.end()) {
	return 1;
    }

    /* no certificate credentials for this identity available */
    return 0;
}

/**
 * start a TLS layer on a connection and set the appropriate mio handlers for SSL/TLS
 *
 * @param m the connection on which the TLS layer should be established
 * @param originator 1 if this side is the originating side, 0 else
 * @param identity our own identity (selector for the used certificate)
 * @return 0 on success, non-zero on failure
 */
int mio_ssl_starttls(mio m, int originator, const char* identity) {
    gnutls_session_t session = NULL;
    gnutls_certificate_credentials_t used_credentials = NULL;
    int ret = 0;

    /* sanity check */
    if (m == NULL)
	return 1;

    /* only start TLS on a connection once */
    if (m->ssl != NULL) {
	log_debug2(ZONE, LOGT_EXECFLOW|LOGT_IO, "cannot start TLS layer on an already encrapted socket (mio=%X)", m);
	return 1;
    }

    /* get the right credentials */
    if (identity != NULL && mio_tls_credentials.find(identity) != mio_tls_credentials.end()) {
	used_credentials = mio_tls_credentials[identity];
    } else {
	used_credentials = mio_tls_credentials["*"];
    }
    if (used_credentials == NULL) {
	log_error(identity, "Cannot start TLS layer for %s - no credentials available, even no default ones", identity);
	return 1;
    }

    log_debug2(ZONE, LOGT_IO, "Establishing TLS layer for %s connection (we=%s, peer=%s, identity=%s)", originator ? "outgoing" : "incoming", m->our_ip, m->peer_ip, identity);

    /* GNU TLS setup for this connection */
    ret = gnutls_init(&session, originator ? GNUTLS_CLIENT : GNUTLS_SERVER);
    if (ret != 0) {
	log_debug2(ZONE, LOGT_IO, "Error initializing session for fd #%i: %s", m->fd, gnutls_strerror(ret));
	return 1;
    }
    log_debug2(ZONE, LOGT_EXECFLOW, "Created new session %X", session);

    /* setting algorithm priorities */
    ret = gnutls_set_default_priority(session);
    if (ret != 0) {
	log_debug2(ZONE, LOGT_IO, "Error setting default priorities for fd #%i: %s", m->fd, gnutls_strerror(ret));
    }

    static const int protocol_priority[] = { GNUTLS_TLS1_1, GNUTLS_TLS1_0, GNUTLS_SSL3, 0 };
    ret = gnutls_protocol_set_priority(session, protocol_priority);
    if (ret < 0) {
	log_notice(identity, "error setting protocol priority: %s", gnutls_strerror(ret));
    }

    static const int kx_priority[] = { GNUTLS_KX_DHE_DSS, GNUTLS_KX_DHE_RSA, GNUTLS_KX_RSA, 0 };
    ret = gnutls_kx_set_priority(session, kx_priority);
    if (ret < 0) {
	log_notice(identity, "error setting key exchange algorithm: %s", gnutls_strerror(ret));
    }

    static const int cipher_priority[] = { GNUTLS_CIPHER_AES_256_CBC, GNUTLS_CIPHER_AES_128_CBC, GNUTLS_CIPHER_3DES_CBC, GNUTLS_CIPHER_ARCFOUR_128, 0 };
    ret = gnutls_cipher_set_priority(session, cipher_priority);
    if (ret < 0) {
	log_notice(identity, "error setting cipher priority: %s", gnutls_strerror(ret));
    }

    /* setting certificate credentials */
    ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, used_credentials);
    if (ret != 0) {
	log_debug2(ZONE, LOGT_IO, "Error setting certificate credentials for fd #%i: %s", m->fd, gnutls_strerror(ret));
    }
    if (!originator) {
	gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);
    }
    gnutls_dh_set_prime_bits(session, 1024);

    /* associate with the socket */
    gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) m->fd);

    /* use new read/write handlers */
    m->mh->read = MIO_SSL_READ;
    m->mh->write = MIO_SSL_WRITE;

    /* TLS handshake */
    m->flags.recall_handshake_when_readable = 0;
    m->flags.recall_handshake_when_writeable = 0;
    ret = gnutls_handshake(session);
    if (ret < 0) {
	if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN) {
	    if (gnutls_record_get_direction(session) == 0) {
		m->flags.recall_handshake_when_readable = 1;
		log_debug2(ZONE, LOGT_IO, "TLS layer needs to read data to complete handshake (mio %X, fd #%i)", m, m->fd);
	    } else {
		m->flags.recall_handshake_when_writeable = 1;
		log_debug2(ZONE, LOGT_IO, "TLS layer needs to write data to complete handshake (mio %X, fd #%i)", m, m->fd);
	    }
	    m->mh->handshake = _mio_tls_cont_handshake_server;
	    m->ssl = session;
	    pool_cleanup(m->p, _mio_ssl_cleanup, (void*)session);
	    return 0;
	}

	/* real error happened */
	mio_close(m);
	gnutls_deinit(session);
	log_debug2(ZONE, LOGT_IO, "TLS handshake failed on socket #%i: %s", m->fd, gnutls_strerror(ret));
	return 1;
    }

    m->k.val = 100;
    m->ssl = session;
    log_debug2(ZONE, LOGT_EXECFLOW, "m->ssl is now %X, session=%X", m->ssl, session);

    pool_cleanup(m->p, _mio_ssl_cleanup, (void*)session);

    log_debug2(ZONE, LOGT_IO, "Established TLS layer on socket %d, mio %X", m->fd, m);

    return 0;
}

/**
 * check if two domains are matching
 *
 * Used to check if a domain in a x509 certificate matches an expected domain name
 *
 * @todo take care of punycode encoded domains in the certificate
 *
 * @todo wildcard matching
 *
 * @param p memory pool, that can be used for the comparison
 * @param cert_dom the domain out of a x509 domain, may contain wildcards as in RFC2818
 * @param true_dom the expected domain (may NOT contain wildcards)
 * @return 0 if the domains are matching, non-zero else
 */
static int mio_tls_cert_match(pool p, const char *cert_dom, const char *true_dom) {
    /* sanity check */
    if (p == NULL || cert_dom == NULL || true_dom == NULL) {
	return 1;
    }

    /* does cert_dom contain wildcards? */
    if (strchr(cert_dom, '*') == NULL) {
	/* no wildcards */

	/* make it a JID to get the domains stringpreped */
	jid jid_cert = jid_new(p, cert_dom);
	jid jid_true = jid_new(p, true_dom);

	/* compare */
	return jid_cmp(jid_cert, jid_true);
    } else {
	/* there are wildcards, match domain name fragment by fragment */

	/* XXX: to be implemented - asume no match for now */
	return 1;
    }
}


/**
 * verify the SSL/TLS certificate of the peer for the given MIO connection
 *
 * @param m the connection for which the peer should be verified
 * @param the JabberID, that the certificate should be checked for, if NULL it is only checked if the certificate is valid and trusted
 * @return 0 the certificate is invalid, 1 the certificate is valid
 */
int mio_ssl_verify(mio m, const char *id_on_xmppAddr) {
    int ret = 0;
    unsigned int status = 0;
    const gnutls_datum_t *cert_list = NULL;
    unsigned int cert_list_size = 0;
    int verification_result = 1;
    int crt_index = 0;
    std::string log_id;

    /* sanity checks */
    if (m==NULL || m->ssl==NULL) {
	return 0;
    }

    /* generate id for logging */
    if (id_on_xmppAddr == NULL) {
	log_id = "<unknown peer>";
    } else {
	log_id = id_on_xmppAddr;
    }

    /* check if the certificate is valid */
    ret = gnutls_certificate_verify_peers2(static_cast<gnutls_session_t>(m->ssl), &status);
    if (ret != 0) {
	log_notice(log_id.c_str(), "TLS cert verification failed: %s", gnutls_strerror(ret));
	return 0;
    }
    if (status != 0) {
	std::ostringstream messages;
	bool got_a_message = false;

	if (status&GNUTLS_CERT_INVALID) {
	    got_a_message = true;
	    messages << "not trusted";
	}
	if (status&GNUTLS_CERT_REVOKED) {
	    if (got_a_message)
		messages << ", ";
	    got_a_message = true;
	    messages << "revoked";
	}
	if (status&GNUTLS_CERT_SIGNER_NOT_FOUND) {
	    if (got_a_message)
		messages << ", ";
	    got_a_message = true;
	    messages << "no known issuer";
	}
	if (status&GNUTLS_CERT_SIGNER_NOT_CA) {
	    if (got_a_message)
		messages << ", ";
	    got_a_message = true;
	    messages << "signer is no CA";
	}
	if (status&GNUTLS_CERT_INSECURE_ALGORITHM) {
	    if (got_a_message)
		messages << ", ";
	    got_a_message = true;
	    messages << "insecure algorithm";
	}

	std::string cert_subject;
	if (gnutls_certificate_type_get(static_cast<gnutls_session_t>(m->ssl)) == GNUTLS_CRT_X509) {
	    cert_list = gnutls_certificate_get_peers(static_cast<gnutls_session_t>(m->ssl), &cert_list_size);
	    if (cert_list != NULL && cert_list_size > 0) {
		gnutls_x509_crt_t cert = NULL;
		ret = gnutls_x509_crt_init(&cert);
		if (ret >= 0) {
		    ret = gnutls_x509_crt_import(cert, &cert_list[crt_index], GNUTLS_X509_FMT_DER);
		    if (ret >= 0) {
			char name[1024];
			size_t name_len = sizeof(name);
			ret = gnutls_x509_crt_get_dn(cert, name, &name_len);
			if (ret >= 0 && name_len > 0) {
			    cert_subject = name;
			} else {
			    cert_subject = gnutls_strerror(ret);
			}
		    } else {
			cert_subject = gnutls_strerror(ret);
		    }
		} else {
		    cert_subject = gnutls_strerror(ret);
		}
		gnutls_x509_crt_deinit(cert);
	    } else {
		cert_subject = "<no cert list>";
	    }
	} else {
	    cert_subject = "<no X.509 cert>";
	}

	log_notice(log_id.c_str(), "Certificate verification failed: %s (%s)", got_a_message ? messages.str().c_str() : "unknown reason", cert_subject.c_str());
	return 0;
    }

    /* check if it is a X.509 certificate */
    if (gnutls_certificate_type_get(static_cast<gnutls_session_t>(m->ssl)) != GNUTLS_CRT_X509) {
	/* no ... we cannot handle other certificates here yet ... declare as invalid */
	log_notice(log_id.c_str(), "Rejecting certificate as it is no X.509 certificate");
	return 0;
    }

    /* get the certificates */
    cert_list = gnutls_certificate_get_peers(static_cast<gnutls_session_t>(m->ssl), &cert_list_size);
    if (cert_list == NULL || cert_list_size <= 0) {
	log_notice(log_id.c_str(), "Problem verifying certificate: No certificate was found!");
	return 0;
    }

    log_debug2(ZONE, LOGT_AUTH, "We have to verify %i certificates for %s", cert_list_size, id_on_xmppAddr);

    /* iterate on the certificates */
    for (crt_index = 0; crt_index < cert_list_size; crt_index++) {
	gnutls_x509_crt_t cert = NULL;
	std::string cert_subject;

	/* initialize X.509 certificate structure */
	ret = gnutls_x509_crt_init(&cert);
	if (ret < 0) {
	    log_warn(log_id.c_str(), "Problem initializing the certificate var. Therefore I cannot verify the certificate.");
	    return 0;
	}

	/* XXX begin debugging only
	 *
	std::ostringstream tmpfilename;
	tmpfilename << "/tmp/";
	if (id_on_xmppAddr != NULL) {
	    tmpfilename << id_on_xmppAddr;
	}
	tmpfilename << "_" << crt_index << ".der";

	std::ofstream tmpfile(tmpfilename.str().c_str());

	for (int c=0; c<cert_list[crt_index].size; c++) {
	    tmpfile.put(cert_list[crt_index].data[c]);	// write is not working because of libpth's definitions
	}

	tmpfile.close();
	 *
	 * XXX end debugging only */

	/* get this certificate */
	ret = gnutls_x509_crt_import(cert, &cert_list[crt_index], GNUTLS_X509_FMT_DER);
	if (ret < 0) {
	    log_warn(log_id.c_str(), "Error in loading certificate %i: %s", crt_index, gnutls_strerror(ret));
	    verification_result = 0;
	    gnutls_x509_crt_deinit(cert);
	    cert = NULL;
	    break;
	}

	/* get the DN of the certificate */
	char name[1024];
	size_t name_len = sizeof(name);
	ret = gnutls_x509_crt_get_dn(cert, name, &name_len);
	if (ret < 0) {
	    log_warn(log_id.c_str(), "Error accessing DN of certificate %i: %s", crt_index, gnutls_strerror(ret));
	} else {
	    cert_subject = name;
	}
	log_debug2(ZONE, LOGT_AUTH, "verifying certificate: %s", cert_subject.c_str());

	/* for the first certificate we have to check the subjectAltNames */
	if (crt_index == 0 && id_on_xmppAddr != NULL) {
	    int ext_count = 0;
	    int found_matching_subjectAltName = 0;
	    int found_any_subjectAltName = 0;
	    int may_match_dNSName = 1;

	    log_debug2(ZONE, LOGT_AUTH, "verifying first certificate in chain ...");

	    /* only pure domains may be matched against dNSName */
	    if (id_on_xmppAddr == NULL || strchr(id_on_xmppAddr, '@') != NULL || strchr(id_on_xmppAddr, '/') != NULL) {
		may_match_dNSName = 0;
	    }

	    /* verify id-on-xmppAddr and dNSName */
	    do {
		unsigned char subjectAltName[2048];
		size_t subjectAltName_size = sizeof(subjectAltName);
		unsigned int is_critical = 0;

		ret = gnutls_x509_crt_get_extension_by_oid(cert, "2.5.29.17", ext_count, subjectAltName, &subjectAltName_size, &is_critical);
		if (ret < 0) {
		    if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			log_debug2(ZONE, LOGT_AUTH, "no more subjectAltName extensions (%i)", ext_count);
		    } else {
			log_warn(log_id.c_str(), "error requesting %i-th subjectAltName: %s (%s)", ext_count, gnutls_strerror(ret), cert_subject.c_str());
		    }
		} else {
		    ASN1_TYPE subjectAltName_element = ASN1_TYPE_EMPTY;
		    int cnt = 0;

		    log_debug2(ZONE, LOGT_AUTH, "got a%s subjectAltName extension", is_critical ? " critical" : "");

		    /* we got a subjectAltName */
		    found_any_subjectAltName = 1;

		    /* init subjectAltName_element */
		    ret = asn1_create_element(mio_tls_asn1_tree, "PKIX1.SubjectAltName", &subjectAltName_element);
		    if (ret != ASN1_SUCCESS) {
			log_warn(log_id.c_str(), "error creating asn1 element for PKIX1.SubjectAltName: %s (%s)", libtasn1_strerror(ret), cert_subject.c_str());
			break;
		    }

		    /* decode the extension */
		    ret = asn1_der_decoding(&subjectAltName_element, subjectAltName, subjectAltName_size, NULL);
		    if (ret != ASN1_SUCCESS) {
			log_warn(log_id.c_str(), "error DER decoding subjectAltName extension: %s (%s)", libtasn1_strerror(ret), cert_subject.c_str());
			asn1_delete_structure(&subjectAltName_element);
			break;
		    }

		    /* subjectAltName is a sequence we have to iterate ... */
		    for (cnt = 1; cnt < 1024 && !found_matching_subjectAltName; cnt++) {
			char cnt_string[6];
			char address_type[32];
			int address_type_len = sizeof(address_type);

			snprintf(cnt_string, sizeof(cnt_string), "?%i", cnt);

			log_debug2(ZONE, LOGT_AUTH, "accessing subjectAltName element %s", cnt_string);

			ret = asn1_read_value(subjectAltName_element, cnt_string, address_type, &address_type_len);
			if (ret == ASN1_ELEMENT_NOT_FOUND) {
			    log_debug2(ZONE, LOGT_AUTH, "no more values in subjectAltName (%s)", cnt_string);
			    break;
			}
			if (ret != ASN1_SUCCESS) {
			    log_notice(log_id.c_str(), "error accessing type for %s in subjectAltName: %s (%s)", cnt_string, libtasn1_strerror(ret), cert_subject.c_str());
			    break;
			}

			log_debug2(ZONE, LOGT_AUTH, "... it is of type %s", address_type);

			/* is it a dNSName? */
			if (j_strncmp(address_type, "dNSName", 8) == 0) {
			    if (!may_match_dNSName) {
				log_debug2(ZONE, LOGT_AUTH, "not checking dNSName, as we are not searching for a domain");
			    } else {
				char access_string[14];
				char dNSName[2048];
				int dNSName_len = sizeof(dNSName);
				pool compare_pool = NULL;

				snprintf(access_string, sizeof(access_string), "%s.dNSName", cnt_string);

				ret = asn1_read_value(subjectAltName_element, access_string, dNSName, &dNSName_len);
				if (ret != ASN1_SUCCESS) {
				    log_notice(log_id.c_str(), "error accessing %s in subjectAltName: %s (%s)", access_string, libtasn1_strerror(ret), cert_subject.c_str());
				    break;
				}

				if (dNSName_len >= sizeof(dNSName)) {
				    log_notice(log_id.c_str(), "got a dNSName which is longer then %i B. Skipping ... (%s)", sizeof(dNSName), cert_subject.c_str());
				    break;
				}

				/* zero terminating the dNSName */
				dNSName[dNSName_len] = 0;
				log_debug2(ZONE, LOGT_AUTH, "found dNSName: %s", dNSName);

				/* get a memory pool for doing comparisons */
				compare_pool = pool_new();

				/* compare the dNSName */
				if (mio_tls_cert_match(compare_pool, dNSName, id_on_xmppAddr) == 0) {
				    found_matching_subjectAltName = 1;
				    log_debug2(ZONE, LOGT_AUTH, "match on dNSName: %s", dNSName);
				}

				/* free memory pool */
				pool_free(compare_pool);
				compare_pool = NULL;
			    }
			} else if (j_strncmp(address_type, "otherName", 10) == 0) {
			    char access_string_type[24];
			    char access_string_value[22];
			    char otherNameType[1024];
			    int otherNameType_len = sizeof(otherNameType);
			    unsigned char otherNameValue[1024];
			    int otherNameValue_len = sizeof(otherNameValue);

			    snprintf(access_string_type, sizeof(access_string_type), "%s.otherName.type-id", cnt_string);
			    snprintf(access_string_value, sizeof(access_string_value), "%s.otherName.value", cnt_string);

			    /* get the OID of the otherName */
			    ret = asn1_read_value(subjectAltName_element, access_string_type, otherNameType, &otherNameType_len);
			    if (ret != ASN1_SUCCESS) {
				log_notice(log_id.c_str(), "error accessing type information %s in subjectAltName: %s (%s)", access_string_type, libtasn1_strerror(ret), cert_subject.c_str());
				break;
			    }

			    /* is it an id-on-xmppAddr */
			    if (j_strncmp(otherNameType, "1.3.6.1.5.5.7.8.5", 18) != 0) {
				log_notice(log_id.c_str(), "ignoring unknown otherName in subjectAltName (%s)", cert_subject.c_str());
				break;
			    }

			    /* get the value of the otherName */
			    ret = asn1_read_value(subjectAltName_element, access_string_value, otherNameValue, &otherNameValue_len);
			    if (ret != ASN1_SUCCESS) {
				log_notice(log_id.c_str(), "error accessing value of othername %s in subjectAltName: %s (%s)", access_string_value, libtasn1_strerror(ret), cert_subject.c_str());
				break;
			    }

			    /* okay we now have an UTF8String ... get the content */
			    {
				ASN1_TYPE directoryString_element = ASN1_TYPE_EMPTY;
				char thisIdOnXMPPaddr[3072];
				int thisIdOnXMPPaddr_len = sizeof(thisIdOnXMPPaddr);
				pool jid_pool = NULL;
				jid cert_jid = NULL;

				ret = asn1_create_element(mio_tls_asn1_tree, "PKIX1.DirectoryString", &directoryString_element);
				if (ret != ASN1_SUCCESS) {
				    log_notice(log_id.c_str(), "error creating DirectoryString element: %s (%s)", libtasn1_strerror(ret), cert_subject.c_str());
				    asn1_delete_structure(&directoryString_element);
				    break;
				}

				ret = asn1_der_decoding(&directoryString_element, otherNameValue, otherNameValue_len, NULL);
				if (ret != ASN1_SUCCESS) {
				    log_notice(log_id.c_str(), "error decoding DirectoryString: %s (%s)", libtasn1_strerror(ret), cert_subject.c_str());
				    asn1_delete_structure(&directoryString_element);
				    break;
				}

				ret = asn1_read_value(directoryString_element, "utf8String", thisIdOnXMPPaddr, &thisIdOnXMPPaddr_len);
				if (ret != ASN1_SUCCESS) {
				    log_notice(log_id.c_str(), "error accessing utf8String of DirectoryString: %s (%s)", libtasn1_strerror(ret), cert_subject.c_str());
				    asn1_delete_structure(&directoryString_element);
				    break;
				}

				if (thisIdOnXMPPaddr_len >= sizeof(thisIdOnXMPPaddr)) {
				    log_notice(log_id.c_str(), "id-on-xmppAddr is %i B long ... ignoring (%s)", thisIdOnXMPPaddr_len, cert_subject.c_str());
				    asn1_delete_structure(&directoryString_element);
				    break;
				}

				/* zero-terminate the string */
				thisIdOnXMPPaddr[thisIdOnXMPPaddr_len] = 0;

				/* nameprep the domain */
				jid_pool = pool_new();
				cert_jid = jid_new(jid_pool, thisIdOnXMPPaddr);

				if (cert_jid == NULL || cert_jid->server == NULL) {
				    cert_jid = NULL;
				    pool_free(jid_pool);
				    jid_pool = NULL;

				    log_notice(log_id.c_str(), "invalid id-on-xmppAddr: %s ... skipping this one (%s)", thisIdOnXMPPaddr, cert_subject.c_str());
				    break;
				}

				log_debug2(ZONE, LOGT_AUTH, "found id-on-xmppAddr: %s", jid_full(cert_jid));

				/* compare */
				if (j_strcmp(id_on_xmppAddr, jid_full(cert_jid)) == 0) {
				    found_matching_subjectAltName = 1;
				    log_debug2(ZONE, LOGT_AUTH, "match on id-on-xmppAddr: %s", thisIdOnXMPPaddr);
				}

				/* free memory needed for nameprepping */
				cert_jid = NULL;
				pool_free(jid_pool);
				jid_pool = NULL;

				/* free memory needed to DER decode utf8String */
				asn1_delete_structure(&directoryString_element);
			    }

			} else {
			    log_notice(log_id.c_str(), "ignoring %s in subjectAltName (%s)", address_type, cert_subject.c_str());
			}
		    }

		    asn1_delete_structure(&subjectAltName_element);
		}

		ext_count++;
	    } while (ret >= 0 && !found_matching_subjectAltName);

	    if (found_any_subjectAltName) {
		if (!found_matching_subjectAltName) {
		    log_notice(log_id.c_str(), "Found subjectAltName, but non matched (%s)", cert_subject.c_str());
		    verification_result = 0;
		    gnutls_x509_crt_deinit(cert);
		    cert = NULL;
		    break;
		}
	    } else {
		/* verify subject */
		if (!gnutls_x509_crt_check_hostname(cert, id_on_xmppAddr)) {
		    log_notice(log_id.c_str(), "Certificate subject does not match. (%s)", cert_subject.c_str());
		    verification_result = 0;
		    gnutls_x509_crt_deinit(cert);
		    cert = NULL;
		    break;
		}
	    }
	}

	/* check expiration */
	if (gnutls_x509_crt_get_expiration_time(cert) < time(NULL)) {
	    log_notice(log_id.c_str(), "Certificate %i has expired (%s)", crt_index, cert_subject.c_str());
	    verification_result = 0;
	    gnutls_x509_crt_deinit(cert);
	    cert = NULL;
	    break;
	}
	if (gnutls_x509_crt_get_activation_time(cert) > time(NULL)) {
	    log_notice(log_id.c_str(), "Certificate %i not yet active (%s)", crt_index, cert_subject.c_str());
	    verification_result = 0;
	    gnutls_x509_crt_deinit(cert);
	    cert = NULL;
	    break;
	}
	gnutls_x509_crt_deinit(cert);
    }
    
    return verification_result;
}

#endif /* HAVE_GNUTLS */
