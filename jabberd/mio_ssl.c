#include "jabberd.h"
#ifdef HAVE_SSL
#include <openssl/err.h>

xht ssl__ctxs;
extern int mio__errno;
extern int mio__ssl_reread;


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
void mio_ssl_init(xmlnode x)
{
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

    log_debug2(ZONE, LOGT_INIT, "MIO SSL init");

    /* Make sure we have a valid xmlnode to play with */
    if(x == NULL && xmlnode_has_children(x))
    {
        log_debug2(ZONE, LOGT_INIT|LOGT_STRANGE, "SSL Init called with invalid xmlnode");
        return;
    }

    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "Handling configuration using: %s", xmlnode2str(x));
    /* Generic SSL Inits */
	OpenSSL_add_all_algorithms();    
    SSL_load_error_strings();

    /* Setup our hashtable */
    ssl__ctxs = xhash_new(19);

    /* Walk our node and add the created contexts */
    for(cur = xmlnode_get_tag(x, "key"); cur != NULL; 
                    cur = xmlnode_get_nextsibling(cur))
    {
	/* ip is the fallback for jabberd 1.4.3 compatibility */
	host = xmlnode_get_attrib(cur, "id");
	if (host == NULL)
	    host = xmlnode_get_attrib(cur, "ip");

        keypath = xmlnode_get_data(cur);

        if(!host || !keypath)
            continue;

        log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "Handling: %s", xmlnode2str(cur));

        ctx=SSL_CTX_new(SSLv23_method());
        if(ctx == NULL)
        {
            unsigned long e;
            static char *buf;
        
            e = ERR_get_error();
            buf = ERR_error_string(e, NULL);
            log_warn(NULL, "Could not create SSL Context: %s", buf);
            return;
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
        if(!SSL_CTX_use_certificate_file(ctx, keypath,SSL_FILETYPE_PEM)) 
        {
            log_warn(NULL, "SSL Error using certificate file");
            SSL_CTX_free(ctx);
            continue;
        }
        if(!SSL_CTX_use_PrivateKey_file(ctx, keypath,SSL_FILETYPE_PEM)) 
        {
            log_warn(NULL, "SSL Error using Private Key file");
            SSL_CTX_free(ctx);
            continue;
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

ssize_t _mio_ssl_read(mio m, void *buf, size_t count)
{
    SSL *ssl;
    ssize_t ret;
    int sret;

    ssl = m->ssl;
    
    if(count <= 0)
        return 0;

    log_debug2(ZONE, LOGT_IO, "Asked to read %d bytes from %d", count, m->fd);
    mio__ssl_reread = 0;

    /*
    if(SSL_get_state(ssl) != SSL_ST_OK)
    {
        sret = SSL_accept(ssl);
        if(sret <= 0)
        {
            unsigned long e;
            static char *buf;
            
            if((SSL_get_error(ssl, sret) == SSL_ERROR_WANT_READ) ||
               SSL_get_error(ssl, sret) == SSL_ERROR_WANT_WRITE)
            {
                log_debug2(ZONE, LOGT_IO, "Read blocked, returning");

                mio__errno = EAGAIN;
                return -1;
            }
            e = ERR_get_error();
            buf = ERR_error_string(e, NULL);
            log_debug2(ZONE, LOGT_IO, "Error from SSL: %s", buf);
            log_debug2(ZONE, LOGT_IO, "SSL Error in SSL_accept call");
            close(m->fd);
            return -1;
        }       
    }
    */
    ret = SSL_read(ssl, (char *)buf, count);

    if (ret == count)
    {
        mio__ssl_reread = 1;
        log_debug2(ZONE, LOGT_IO, "SSL Asked to reread from %d", m->fd);
    }

    if (ret < 0) {
	int ssl_error;

	ssl_error = SSL_get_error(ssl, ret);
	if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE
		|| ssl_error == SSL_ERROR_WANT_CONNECT || ssl_error == SSL_ERROR_WANT_ACCEPT) {
	    mio__errno = EAGAIN;
	    return -1;
	}
    } else if (ret > 0) {
	log_debug2(ZONE, LOGT_IO, "Read from SSL/TLS socket: %.*s", ret, buf);
    }

    return ret;
}

ssize_t _mio_ssl_write(mio m, const void *buf, size_t count)
{
    int ret;
    SSL *ssl;
    ssl = m->ssl;
   
    /*
    if(SSL_get_state(ssl) != SSL_ST_OK)
    {
        int sret;

        sret = SSL_accept(ssl);
        if(sret <= 0){
            unsigned long e;
            static char *buf;
            
            if((SSL_get_error(ssl, sret) == SSL_ERROR_WANT_READ) ||
               SSL_get_error(ssl, sret) == SSL_ERROR_WANT_WRITE)
            {
                log_debug2(ZONE, LOGT_IO, "Write blocked, returning");
                
                mio__errno = EAGAIN;
                return -1;
            }
            e = ERR_get_error();
            buf = ERR_error_string(e, NULL);
            log_debug2(ZONE, LOGT_IO, "Error from SSL: %s", buf);
            log_debug2(ZONE, LOGT_IO, "SSL Error in SSL_accept call");
            close(m->fd);
            return -1;
        }       
    }
    */
    log_debug2(ZONE, LOGT_IO, "writing to SSL/TLS socket: %.*s", count, buf);
    ret = SSL_write(ssl, buf, count);

    if (ret < 0) {
	int ssl_error;

	ssl_error = SSL_get_error(ssl, ret);
	if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE
		|| ssl_error == SSL_ERROR_WANT_CONNECT || ssl_error == SSL_ERROR_WANT_ACCEPT) {
	    mio__errno = EAGAIN;
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

#endif /* HAVE_SSL */
