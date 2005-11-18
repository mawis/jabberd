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

/**
 * the TLS credentials
 */
gnutls_certificate_credentials_t mio_tls_x509_cred = NULL;

/**
 * initialize the mio SSL/TLS module using the GNU TLS library
 *
 * @param x xmlnode containing the configuration information (the io/tls element)
 */
void mio_ssl_init(xmlnode x) {
    xmlnode cur = NULL;
    int ret = 0;
    static gnutls_dh_params_t mio_tls_dh_params;

    log_debug2(ZONE, LOGT_IO, "MIO TLS init (GNU TLS)");

    /* initialize the GNU TLS library */
    ret = gnutls_global_init();
    if (ret != 0) {
	log_error(ZONE, "Error initializing GNU TLS library: %s", gnutls_strerror(ret));
	/* XXX what to do now? */
    }

    /* load certificates and such ... */
    ret = gnutls_certificate_allocate_credentials (&mio_tls_x509_cred);
    if (ret != 0) {
	log_error(ZONE, "Error allocating GNU TLS credentials: %s", gnutls_strerror(ret));
	/* XXX what to do now? */
    }

    for (cur = xmlnode_get_firstchild(x); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	if (cur->type != NTYPE_TAG) {
	    continue;
	}
	/* it's a key */
	if (j_strcmp(xmlnode_get_name(cur), "key") == 0) {
	    char *file_to_use = xmlnode_get_data(cur);

	    if (file_to_use == NULL) {
		log_warn(NULL, "skipping a key element in the TLS configuration as no file is specified");
		continue;
	    }
	    ret = gnutls_certificate_set_x509_key_file(mio_tls_x509_cred, file_to_use, file_to_use, GNUTLS_X509_FMT_PEM);
	    if (ret < 0) {
		log_error(ZONE, "Error loading key file %s: %s", file_to_use, gnutls_strerror(ret));
	    }
	}
	/* it's a ca cert */
	if (j_strcmp(xmlnode_get_name(cur), "cacertfile") == 0) {
	    char *file_to_use = xmlnode_get_data(cur);

	    if (file_to_use == NULL) {
		log_warn(NULL, "skipping a cacertfile element in the TLS configuration as no file is specified");
		continue;
	    }
	    ret = gnutls_certificate_set_x509_trust_file(mio_tls_x509_cred, file_to_use, GNUTLS_X509_FMT_PEM);
	    if (ret < 0) {
		log_error(ZONE, "Error loading cacert file %s: %s", file_to_use, gnutls_strerror(ret));
	    }
	}
    }

    /* init DH */
    ret = gnutls_dh_params_init(&mio_tls_dh_params);
    if (ret < 0) {
	log_error(ZONE, "Error initializing DH params: %s", gnutls_strerror(ret));
    }
    ret = gnutls_dh_params_generate2(mio_tls_dh_params, 1024);
    if (ret < 0) {
	log_error(ZONE, "Error generating DH params: %s", gnutls_strerror(ret));
    }
    gnutls_certificate_set_dh_params(mio_tls_x509_cred, mio_tls_dh_params);
}

void _mio_ssl_cleanup(void *arg) {
    gnutls_session_t session = (gnutls_session_t)arg;

    log_debug2(ZONE, LOGT_IO, "GNU TLS session cleanup for %X", session);
    gnutls_deinit(session);
}

ssize_t _mio_ssl_read(mio m, void *buf, size_t count) {
    int ret = 0;

    /* sanity checks */
    if (count <= 0 || buf == NULL || m == NULL) {
	return 0;
    }

    log_debug2(ZONE, LOGT_IO, "Asked to read %i B from %i (m->ssl = %X)", count, m->fd, m->ssl);

    /* resetting flags, we set them again if neccessary */
    m->flags.tls_reread = 0;
    m->flags.recall_read_when_readable = 0;
    m->flags.recall_read_when_writeable = 0;

    /* try to read data */
    ret = gnutls_record_recv(m->ssl, (char *)buf, count);

    /* if we read as much as possible, there might be more */
    if (ret == count) {
	m->flags.tls_reread = 1;
	log_debug2(ZONE, LOGT_IO, "GNU TLS asked to reread from %d", m->fd);
    } else if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN) {
	if (gnutls_record_get_direction(m->ssl) == 0) {
	    m->flags.recall_read_when_readable = 1;
	} else {
	    m->flags.recall_read_when_writeable = 1;
	}
	return -1;
    } else if (ret < 0) {
	log_debug2(ZONE, LOGT_IO, "Reading failed on socket #%i: %s", m->fd, gnutls_strerror(ret));
	return -1;
    } else if (ret > 0) {
	log_debug2(ZONE, LOGT_IO, "Read from TLS socket: %.*s", ret, buf);
    }

    return ret;
}

ssize_t _mio_ssl_write(mio m, const void *buf, size_t count) {
    int ret = 0;

    /* sanity checks */
    if (m == NULL || buf == NULL || count == 0) {
	return -1;
    }

    log_debug2(ZONE, LOGT_IO, "writing to TLS socket: %.*s", count, buf);

    /* resetting flags, we set them again if neccessary */
    m->flags.recall_write_when_readable = 0;
    m->flags.recall_write_when_writeable = 0;

    /* try to write data */
    ret = gnutls_record_send(m->ssl, buf, count);

    if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN) {
	if (gnutls_record_get_direction(m->ssl) == 0) {
	    m->flags.recall_write_when_readable = 1;
	} else {
	    m->flags.recall_write_when_writeable = 1;
	}
	return -1;
    } else if (ret < 0) {
	log_debug2(ZONE, LOGT_IO, "Writing failed on socket #%i: %s", m->fd, gnutls_strerror(ret));
	return -1;
    }
    
    return ret;
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
    ret = gnutls_handshake(m->ssl);
    if (ret >= 0) {
	/* reset the handler for handshake */
	m->mh->handshake = NULL;
	log_debug2(ZONE, LOGT_IO, "TLS handshake finished for fd #%i", m->fd);
	return 1;
    } else if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
	if (gnutls_record_get_direction(m->ssl) == 0) {
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
    return m->ssl == NULL ? 0 : gnutls_cipher_get_key_size(gnutls_cipher_get(m->ssl));
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

    /* XXX: check if we have a certificate for the requested domain */

    /* XXX: for now just asume we can */
    return 1;
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
    int ret = 0;

    /* sanity check */
    if (m == NULL)
	return 1;

    /* only start TLS on a connection once */
    if (m->ssl != NULL) {
	log_debug2(ZONE, LOGT_EXECFLOW|LOGT_IO, "cannot start TLS layer on an already encrapted socket (mio=%X)", m);
	return 1;
    }

    log_debug2(ZONE, LOGT_IO, "Establishing TLS layer for %s connection (we=%s, peer=%s, identity=%s)", originator ? "outgoing" : "incoming", m->our_ip, m->peer_ip, identity);

    /* GNU TLS setup for this connection */
    ret = gnutls_init(&session, originator ? GNUTLS_CLIENT : GNUTLS_SERVER);
    if (ret != 0) {
	log_debug2(ZONE, LOGT_IO, "Error initializing session for fd #%i: %s", m->fd, gnutls_strerror(ret));
    }
    log_debug2(ZONE, LOGT_EXECFLOW, "Created new session %X", session);
    ret = gnutls_set_default_priority(session);
    if (ret != 0) {
	log_debug2(ZONE, LOGT_IO, "Error setting default priorities for fd #%i: %s", m->fd, gnutls_strerror(ret));
    }
    ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, mio_tls_x509_cred);	/* XXX: different credentials based on IP */
    if (ret != 0) {
	log_debug2(ZONE, LOGT_IO, "Error setting default priorities for fd #%i: %s", m->fd, gnutls_strerror(ret));
    }
    if (!originator) {
	gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);
    }
    gnutls_dh_set_prime_bits(session, 1024);

    /* associate with the socket */
    gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) m->fd);

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

    return 1;
}

int mio_ssl_verify(mio m, const char *id_on_xmppAddr) {
    return 0;
}

#endif /* HAVE_GNUTLS */
