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
 * @file mio_ssl.c
 * @brief MIO read/write functions to read/write on TLS encrypted sockets and handling for TLS in general
 */

#include "jabberd.h"
#ifdef HAVE_SSL
#include <openssl/err.h>

xht ssl__ctxs;

#ifndef NO_RSA
/* This function will generate a temporary key for us */
RSA *_ssl_tmp_rsa_cb(SSL *ssl, int export, int keylength)
{
    RSA *rsa_tmp = NULL;

    rsa_tmp = RSA_generate_key(keylength, RSA_F4, NULL, NULL);
    if(!rsa_tmp) {
        log_debug2(ZONE, LOGT_INIT, "Error generating temp RSA key");
        return NULL;
    }

    return rsa_tmp;
}
#endif /* NO_RSA */

/**
 * verify callback
 *
 * do not close connections if client certificate not presented or invalid
 *
 * @param pre_ok unused/ignored
 * @param store_ctx unused/ignored
 * @return always 1
 */
static int _mio_ssl_verify_accept_all(int pre_ok, X509_STORE_CTX *store_ctx) {
    return 1;
}

/***************************************************************************
 * This can return whatever we need, it is just designed to read a xmlnode
 * and hash the SSL contexts it creates from the keys in the node
 *
 * Sample node:
 * <ssl>
 *   <key ip='192.168.1.100'>/path/to/the/key/file.pem</key>
 *   <key ip='192.168.1.1'>/path/to/the/key/file.pem</key>
 * </ssl>   
 **************************************************************************/
void mio_ssl_init(xmlnode x) {
/* PSEUDO CODE

  for $key in children(xmlnode x)
  {
      - SSL init
      - Load key into SSL ctx
      - Hash ctx based on hostname
  }

  register a cleanup function to free our contexts
*/

    SSL_CTX *ctx = NULL;
    xmlnode cur;
    char *host;
    char *keypath;
    char *cafile = NULL;

    log_debug2(ZONE, LOGT_INIT, "MIO SSL init");

    /* Make sure we have a valid xmlnode to play with */
    if (x == NULL && xmlnode_has_children(x)) {
        log_debug2(ZONE, LOGT_INIT|LOGT_STRANGE, "SSL Init called with invalid xmlnode");
        return;
    }

    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "Handling configuration using: %s", xmlnode2str(x));
    /* Generic SSL Inits */
    OpenSSL_add_all_algorithms();    
    SSL_load_error_strings();
    SSL_library_init();

    /* Setup our hashtable */
    ssl__ctxs = xhash_new(19);

    /* which CAs to use? */
    cafile = xmlnode_get_tag_data(x, "cacertfile");

    /* Walk our node and add the created contexts */
    for(cur = xmlnode_get_tag(x, "key"); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	/* we only care for the <key/> elements */
	if (cur->type != NTYPE_TAG)
	    continue;
	if (j_strcmp(xmlnode_get_name(cur), "key") != 0)
	    continue;

	/* ip is the fallback for jabberd 1.4.3 compatibility */
	host = xmlnode_get_attrib(cur, "id");
	if (host == NULL)
	    host = xmlnode_get_attrib(cur, "ip");

        keypath = xmlnode_get_data(cur);

        if (!host || !keypath)
            continue;

        log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "Handling: %s", xmlnode2str(cur));

        ctx=SSL_CTX_new(SSLv23_method());
        if (ctx == NULL) {
            unsigned long e;
            static char *buf;
        
            e = ERR_get_error();
            buf = ERR_error_string(e, NULL);
            log_warn(host, "Could not create SSL Context: %s", buf);
            continue;
        }

#ifndef NO_RSA
        log_debug2(ZONE, LOGT_INIT, "Setting temporary RSA callback");
        SSL_CTX_set_tmp_rsa_callback(ctx, _ssl_tmp_rsa_cb);
#endif /* NO_RSA */

        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);

        /* XXX I would like to make this a configurable option */
        /* 
         SSL_CTX_set_timeout(ctx, session_timeout);
         */

        /* Setup the keys and certs */
        log_debug2(ZONE, LOGT_INIT, "Loading SSL certificate %s for %s", keypath, host);
        if (!SSL_CTX_use_certificate_file(ctx, keypath,SSL_FILETYPE_PEM)) {
            log_warn(NULL, "SSL Error using certificate file: %s", keypath);
            SSL_CTX_free(ctx);
            continue;
        }
        if (!SSL_CTX_use_PrivateKey_file(ctx, keypath,SSL_FILETYPE_PEM)) {
            log_warn(NULL, "SSL Error using Private Key file");
            SSL_CTX_free(ctx);
            continue;
        }

	/* setup options */
	if (xmlnode_get_attrib(cur, "no-ssl-v2") != NULL) {
	    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	}
	if (xmlnode_get_attrib(cur, "no-ssl-v3") != NULL) {
	    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
	}
	if (xmlnode_get_attrib(cur, "no-tls-v1") != NULL) {
	    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
	}
	if (xmlnode_get_attrib(cur, "enable-workarounds") != NULL) {
	    SSL_CTX_set_options(ctx, SSL_OP_ALL);
	}
	if (xmlnode_get_attrib(cur, "ciphers") != NULL) {
	    if (!SSL_CTX_set_cipher_list(ctx, xmlnode_get_attrib(cur, "ciphers"))) {
		log_warn(NULL, "SSL Error selecting ciphers");
		SSL_CTX_free(ctx);
		continue;
	    }
	}

	/* load CAs for this context */
	if (cafile != NULL && !SSL_CTX_load_verify_locations(ctx, cafile, NULL)) {
            unsigned long e;
            static char *buf;
        
            e = ERR_get_error();
            buf = ERR_error_string(e, NULL);
            log_warn(host, "Could not load file the CA certs for verification: %s", buf);
	    continue;
	}
	/* set which CAs we advertize to clients for client auth */
	if (cafile != NULL) {
	    STACK_OF(X509_NAME) *stack_of_names = SSL_load_client_CA_file(cafile);
	    if (stack_of_names == NULL) {
		unsigned long e;
		static char *buf;
	    
		e = ERR_get_error();
		buf = ERR_error_string(e, NULL);
		log_warn(host, "Could not set names of CAs for client authentication: %s", buf);
		continue;
	    }
	    SSL_CTX_set_client_CA_list(ctx, stack_of_names);
	    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE, _mio_ssl_verify_accept_all);
	}
	
        xhash_put(ssl__ctxs, host, ctx);
        log_debug2(ZONE, LOGT_INIT|LOGT_IO, "Added context %x for %s", ctx, host);
    }
        
}

void _mio_ssl_cleanup(void *arg)
{
    SSL *ssl = (SSL *)arg;

    log_debug2(ZONE, LOGT_CLEANUP, "SSL Cleanup for %x", ssl);
    SSL_free(ssl);
}

ssize_t _mio_ssl_read(mio m, void *buf, size_t count) {
    SSL *ssl;
    ssize_t ret;
    int sret;

    ssl = m->ssl;
    
    if(count <= 0)
        return 0;

    log_debug2(ZONE, LOGT_IO, "Asked to read %d bytes from %d", count, m->fd);

    /* we are rereading, gets set again if neccessary */
    m->flags.ssl_reread = 0;

    /* we are recalling, reset the flags - if neccessary, they are set again later */
    m->flags.recall_read_when_readable = 0;
    m->flags.recall_read_when_writeable = 0;

    /* try to read data from the OpenSSL library */
    ret = SSL_read(ssl, (char *)buf, count);

    /* if we read as much as possible, there might be more */
    if (ret == count) {
	m->flags.ssl_reread = 1;
        log_debug2(ZONE, LOGT_IO, "SSL Asked to reread from %d", m->fd);
    }

    if (ret < 0) {
	int ssl_error;

	ssl_error = SSL_get_error(ssl, ret);
	switch (ssl_error) {
	    case SSL_ERROR_WANT_READ:
		/* we have to recall SSL_read() as OpenSSL could not read enough data */
		m->flags.recall_read_when_readable = 1;
		return -1;
	    case SSL_ERROR_WANT_WRITE:
		/* we have to recall SSL_read() as OpenSSL could not write all data */
		m->flags.recall_read_when_writeable = 1;
		return -1;
	}
    } else if (ret > 0) {
	log_debug2(ZONE, LOGT_IO, "Read from SSL/TLS socket: %.*s", ret, buf);
    }

    return ret;
}

ssize_t _mio_ssl_write(mio m, const void *buf, size_t count) {
    int ret;
    SSL *ssl;
    ssl = m->ssl;
   
    log_debug2(ZONE, LOGT_IO, "writing to SSL/TLS socket: %.*s", count, buf);

    /* we are recalling write, reset flags - they get set again if neccessary */
    m->flags.recall_write_when_readable = 0;
    m->flags.recall_write_when_writeable = 0;

    /* try to write data to the OpenSSL library */
    ret = SSL_write(ssl, buf, count);

    if (ret < 0) {
	int ssl_error;

	ssl_error = SSL_get_error(ssl, ret);
	switch (ssl_error) {
	    case SSL_ERROR_WANT_READ:
		m->flags.recall_write_when_readable = 1;
		return -1;
	    case SSL_ERROR_WANT_WRITE:
		m->flags.recall_write_when_writeable = 1;
		return -1;
	}
    }

    return ret;
}

int _mio_ssl_accept(mio m, struct sockaddr *serv_addr, socklen_t *addrlen)
{
    SSL *ssl=NULL;
    SSL_CTX *ctx = NULL;
    int fd;
    int sret;
    int flags;

    fd = accept(m->fd, serv_addr, addrlen);

    /* set the socket to non-blocking as this is not
       inherited */
    flags =  fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);

    if(m->ip == NULL)
    {
        log_warn(ZONE, "SSL accept but no IP given in configuration");
        return -1;
    }

    ctx = xhash_get(ssl__ctxs, m->ip);
    if(ctx == NULL)
    {
        log_warn(NULL, "No SSL key configured for IP %s", m->ip);
        return -1;
    }
    ssl = SSL_new(ctx);
    log_debug2(ZONE, LOGT_IO, "SSL accepting socket from %s with new session %x",
                    m->ip, ssl);
    SSL_set_fd(ssl, fd);
    SSL_set_accept_state(ssl);
    sret = SSL_accept(ssl);
    if(sret <= 0)
    {
        unsigned long e;
        static char *buf;
        
        if((SSL_get_error(ssl, sret) == SSL_ERROR_WANT_READ) ||
           (SSL_get_error(ssl, sret) == SSL_ERROR_WANT_WRITE))
        {
            m->ssl = ssl;
            log_debug2(ZONE, LOGT_IO, "Accept blocked, returning");
            return fd;
        }
        e = ERR_get_error();
        buf = ERR_error_string(e, NULL);
        log_debug2(ZONE, LOGT_IO, "Error from SSL: %s", buf);
        log_debug2(ZONE, LOGT_IO, "SSL Error in SSL_accept call");
        SSL_free(ssl);
        close(fd);
        return -1;
    }

    m->k.val = 100;
    m->ssl = ssl;

    log_debug2(ZONE, LOGT_IO, "Accepted new SSL socket %d for %s", fd, m->ip);

    return fd;
}

/**
 * connect to an other host using TLS
 *
 * @todo I don't think this function works. ssl is not initialized.
 *
 * @param m the mio to use
 * @param serv_addr where to connect to
 * @param addrlen length of the address structure
 * @return file descriptor of the new connection, -1 on failure
 */
int _mio_ssl_connect(mio m, struct sockaddr *serv_addr, socklen_t addrlen)
{

    /* PSEUDO
     I need to actually look this one up, but I assume it's similar to the
       SSL accept stuff.
    */
    SSL *ssl=NULL;
    SSL_CTX *ctx = NULL;
    int fd;

    log_debug2(ZONE, LOGT_IO, "Connecting new SSL socket for %s", m->ip);
    ctx = xhash_get(ssl__ctxs, m->ip);
    
    fd = connect(m->fd, serv_addr, addrlen);
    SSL_set_fd(ssl, fd);
    if(SSL_connect(ssl) <= 0){
        log_debug2(ZONE, LOGT_IO, "SSL Error in SSL_connect call");
        SSL_free(ssl);
        close(fd);
        return -1;
    }

    pool_cleanup(m->p, _mio_ssl_cleanup, (void *)ssl);

    m->ssl = ssl;

    return fd;
}

/**
 * check if a connection is encrypted
 *
 * @param m the connection
 * @return 0 if the connection is not encrypted, 1 if the connection is integrity protected, >1 if encrypted
 */
int mio_is_encrypted(mio m) {
#ifdef HAVE_SSL
    return m->ssl == NULL ? 0 : SSL_get_cipher_bits(m->ssl, NULL);
#else
    return 0;
#endif
}

/**
 * check if it would be possible to start TLS on a connection
 *
 * @param m the connection
 * @param identity our own identity (check if certificate is present)
 * @return 0 if it is impossible, 1 if it is possible
 */
int mio_ssl_starttls_possible(mio m, const char* identity) {
    /* don't start TLS if the connection already uses TLS */
    if (m->ssl != NULL)
	return 0;

    /* it is possible, if we have a certificate for this identity */
    if (xhash_get(ssl__ctxs, identity))
	return 1;

    /* it is possible, if there is a default certificate */
    if (xhash_get(ssl__ctxs, "*"))
	return 1;

    /* else it's not possible */
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
    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;
    int sret = 0;
    
    /* only start TLS once */
    if (m->ssl != NULL) {
	log_debug2(ZONE, LOGT_IO, "cannot start tls on an already encrypted socket");
	return 1;
    }

    log_debug2(ZONE, LOGT_IO, "Starting TLS layer on an existing connection for identity %s on fd %i, orig=%i", identity, m->fd, originator);

    /* openssl setup for this conn */
    ctx = xhash_get(ssl__ctxs, identity);
    if (ctx == NULL) {
	ctx = xhash_get(ssl__ctxs, "*");
    }
    if (ctx == NULL) {
        log_warn(NULL, "No TLS key configured for identity %s. Cannot start TLS layer.", identity);
	mio_close(m);
	return 1;
    }
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, m->fd);

    /* start ssl/tls */
    sret = originator ? SSL_connect(ssl) : SSL_accept(ssl);
    if(sret <= 0)
    {
        unsigned long e;
        static char *buf;
        
        if((SSL_get_error(ssl, sret) == SSL_ERROR_WANT_READ) ||
           (SSL_get_error(ssl, sret) == SSL_ERROR_WANT_WRITE))
        {
            m->ssl = ssl;
	    m->mh->read = MIO_SSL_READ;
	    m->mh->write = MIO_SSL_WRITE;
            log_debug2(ZONE, LOGT_IO, "TLS %s for existing connection blocked, returning", originator ? "connect" : "accept");
            return 0;
        }
        e = ERR_get_error();
        buf = ERR_error_string(e, NULL);
        log_debug2(ZONE, LOGT_IO, "Error from SSL: %s", buf);
        log_debug2(ZONE, LOGT_IO, "SSL Error in SSL_%s call", originator ? "connect" : "accept");
        SSL_free(ssl);
	mio_close(m);
        return 1;
    }

    m->k.val = 100;
    m->ssl = ssl;
    m->mh->read = MIO_SSL_READ;
    m->mh->write = MIO_SSL_WRITE;

    log_debug2(ZONE, LOGT_IO, "TLS established on fd %i", m->fd);

    return 0;
}

/**
 * verify the SSL/TLS certificate of the peer for the given MIO connection
 *
 * @param m the connection for which the peer should be verified
 * @param the JabberID, that the certificate should be checked for, if NULL it is only checked if the certificate is valid and trusted
 * @return 0 the certificate is invalid, 1 the certificate is valid
 */
int mio_ssl_verify(mio m, const char *id_on_xmppAddr) {
    long verify_result = 0;
    X509 *peer_cert = NULL;
    X509_NAME *peer_subject_name = NULL;
    ASN1_OBJECT *obj_id_on_xmppAddr = NULL;
    int lastpos = 0;
    int id_on_xmppAddr_count = 0;
    pool p = NULL;
    jid jid_xmppAddr = NULL;

    /* sanity checks */
    if (m == NULL || m->ssl == NULL)
	return 0;

    /* check if we have a peer certificate */
    peer_cert = SSL_get_peer_certificate(m->ssl);
    if (peer_cert == NULL) {
	log_notice(id_on_xmppAddr, "TLS verification failed: no peer certificate");
	return 0;
    }

    /* check if the certificate is valid */
    verify_result = SSL_get_verify_result(m->ssl);
    if (verify_result != X509_V_OK) {
	switch (verify_result) {
	    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		log_notice(id_on_xmppAddr, "TLS verification failed: unable to get issuer certificate");
		break;
	    case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
		log_notice(id_on_xmppAddr, "TLS verification failed: unable to decrypt certificate's signature");
		break;
	    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
		log_notice(id_on_xmppAddr, "TLS verification failed: unable to decode issuer public key");
		break;
	    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
		log_notice(id_on_xmppAddr, "TLS verification failed: certificate signature failure");
		break;
	    case X509_V_ERR_CERT_NOT_YET_VALID:
		log_notice(id_on_xmppAddr, "TLS verification failed: certificate is not yet valid");
		break;
	    case X509_V_ERR_CERT_HAS_EXPIRED:
		log_notice(id_on_xmppAddr, "TLS verification failed: certificate has expired");
		break;
	    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		log_notice(id_on_xmppAddr, "TLS verification failed: format error in certificate's notBefore field");
		break;
	    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		log_notice(id_on_xmppAddr, "TLS verification failed: format error in certificate's notAfter field");
		break;
	    case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
		log_notice(id_on_xmppAddr, "TLS verification failed: format error in CRL's lastUpdate field");
		break;
	    case X509_V_ERR_OUT_OF_MEM:
		log_notice(id_on_xmppAddr, "TLS verification failed: out of memory");
		break;
	    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		log_notice(id_on_xmppAddr, "TLS verification failed: self signed certificate");
		break;
	    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
		log_notice(id_on_xmppAddr, "TLS verification failed: self signed certificate in certificate chain");
		break;
	    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		log_notice(id_on_xmppAddr, "TLS verification failed: unable to get local issuer certificate");
		break;
	    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
		log_notice(id_on_xmppAddr, "TLS verification failed: unable to verify the first certificate");
		break;
	    case X509_V_ERR_INVALID_CA:
		log_notice(id_on_xmppAddr, "TLS verification failed: invalid CA certificate");
		break;
	    case X509_V_ERR_PATH_LENGTH_EXCEEDED:
		log_notice(id_on_xmppAddr, "TLS verification failed: path length constraint exceeded");
		break;
	    case X509_V_ERR_INVALID_PURPOSE:
		log_notice(id_on_xmppAddr, "TLS verification failed: unsupported certificate purpose");
		break;
	    case X509_V_ERR_CERT_UNTRUSTED:
		log_notice(id_on_xmppAddr, "TLS verification failed: certificate not trusted");
		break;
	    case X509_V_ERR_CERT_REJECTED:
		log_notice(id_on_xmppAddr, "TLS verification failed: certificate rejected");
		break;
	    case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
		log_notice(id_on_xmppAddr, "TLS verification failed: subject issuer mismatch");
		break;
	    case X509_V_ERR_AKID_SKID_MISMATCH:
		log_notice(id_on_xmppAddr, "TLS verification failed: authority and subject key identifier mismatch");
		break;
	    case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
		log_notice(id_on_xmppAddr, "TLS verification failed: authority and issuer serial number mismatch");
		break;
	    case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
		log_notice(id_on_xmppAddr, "TLS verification failed: key usage does not include certificate signing");
		break;
	}
	return 0;
    }

    /* if no id_on_xmppAddr is given, we don't have to check the subject: consider cert valid! */
    if (id_on_xmppAddr == NULL)
	return 1;

    /* get a memory pool for the checks */
    p = pool_new();
    jid_xmppAddr = jid_new(p, id_on_xmppAddr);

    /* check the subject of the certificate */
    peer_subject_name = X509_get_subject_name(peer_cert);

    /* check id-on-xmppAddr first */
    obj_id_on_xmppAddr = OBJ_txt2obj("1.3.6.1.5.5.7.8.5", 1);
    for (lastpos = X509_NAME_get_index_by_OBJ(peer_subject_name, obj_id_on_xmppAddr, -1); lastpos!=-1; lastpos = X509_NAME_get_index_by_OBJ(peer_subject_name, obj_id_on_xmppAddr, lastpos)) {
	X509_NAME_ENTRY *name_entry = NULL;
	ASN1_STRING *asn1_data = NULL;
	int string_len = 0;
	unsigned char *string_buf = NULL;
	jid jid_x509 = NULL;

	/* count number of found id-on-xmppAddr */
	id_on_xmppAddr_count++;

	/* get the id-on-xmppAddr as UTF-8 string */
	name_entry = X509_NAME_get_entry(peer_subject_name, lastpos);
	asn1_data = X509_NAME_ENTRY_get_data(name_entry);
	string_len = ASN1_STRING_to_UTF8(&string_buf, asn1_data);

	/* check it */
	jid_x509 = jid_new(p, (const char *)string_buf);
	if (jid_cmp(jid_xmppAddr, jid_x509) == 0) {
	    /* match! */
	    OPENSSL_free(string_buf);
	    log_notice(id_on_xmppAddr, "TLS verification success: subject match on id-on-xmppAddr");
	    pool_free(p);
	    return 1;
	}

	if (string_buf != NULL)
	    OPENSSL_free(string_buf);
    }

    /* if id-on-xmppAddr was present, but no match, the cert is not okay */
    if (id_on_xmppAddr_count > 0) {
	log_notice(id_on_xmppAddr, "TLS verification failed: id-on-xmppAddr present but no match");
	pool_free(p);
	return 0;
    }

    /* check CN */
    for (lastpos = X509_NAME_get_index_by_NID(peer_subject_name, NID_commonName, -1); lastpos != -1; lastpos = X509_NAME_get_index_by_NID(peer_subject_name, NID_commonName, lastpos)) {
	X509_NAME_ENTRY *name_entry = NULL;
	ASN1_STRING *asn1_data = NULL;
	int string_len = 0;
	unsigned char *string_buf = NULL;
	jid jid_x509 = NULL;

	/* get the commonName as UTF-8 string */
	name_entry = X509_NAME_get_entry(peer_subject_name, lastpos);
	asn1_data = X509_NAME_ENTRY_get_data(name_entry);
	string_len = ASN1_STRING_to_UTF8(&string_buf, asn1_data);

	/* special check for *.domain CNs (but only for domains, not in other JIDs) */
	if (string_len > 2 && string_buf != NULL && strchr((const char *)string_buf, '@') == NULL && strchr((const char *)string_buf, '/') == NULL && j_strncmp((const char *)string_buf, "*.", 2) == 0) {
	    char *preped_cert_domain = jid_full(jid_new(p, (const char *)string_buf+2));
	    int id_on_xmppAddr_len = j_strlen(id_on_xmppAddr);

	    /* only check if our expected domain is at least as long as the wildcard string (there must be a subdomain!) */
	    if (id_on_xmppAddr_len > j_strlen(preped_cert_domain)+1) {
		if (j_strcmp(id_on_xmppAddr+id_on_xmppAddr_len-j_strlen(preped_cert_domain), preped_cert_domain) == 0 && id_on_xmppAddr[id_on_xmppAddr_len-j_strlen(preped_cert_domain)-1] == '.') {
		    /* match! */
		    OPENSSL_free(string_buf);
		    log_notice(id_on_xmppAddr, "TLS verification success: subject match on commonName (wildcard-match: %s against *.%s", id_on_xmppAddr, preped_cert_domain);
		    pool_free(p);
		    return 1;
		}
	    }

	} else {
	    /* standard check: try to take it as a JID */
	    jid_x509 = jid_new(p, (const char *)string_buf);
	    if (jid_cmp(jid_xmppAddr, jid_x509) == 0) {
		/* match! */
		OPENSSL_free(string_buf);
		log_notice(id_on_xmppAddr, "TLS verification success: subject match on commonName");
		pool_free(p);
		return 1;
	    }
	}

	if (string_buf != NULL)
	    OPENSSL_free(string_buf);
    }

    /* neither id-on-xmppAddr nor commonName matched: certificate is invalid */
    log_notice(id_on_xmppAddr, "TLS verification failed: neither id-on-xmppAddr (prefered) nor commonName matched expected address");
    pool_free(p);
    return 0;
}

#endif /* HAVE_SSL */
