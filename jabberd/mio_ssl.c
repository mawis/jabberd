#include "jabberd.h"

#ifdef HAVE_SSL
HASHTABLE ssl__ctxs;

#ifndef NO_RSA
/* This function will generate a temporary key for us */
RSA *_ssl_tmp_rsa_cb(SSL *ssl, int export, int keylength)
{
    RSA *rsa_tmp = NULL;

    rsa_tmp = RSA_generate_key(keylength, RSA_F4, NULL, NULL);
    if(!rsa_tmp) {
        log_debug(ZONE, "Error generating temp RSA key");
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

    log_debug(ZONE, "MIO SSL init");

    /* Make sure we have a valid xmlnode to play with */
    if(x == NULL && xmlnode_has_children(x))
    {
        log_debug(ZONE, "SSL Init called with invalid xmlnode");
        return;
    }

    /* Generic SSL Inits */
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();

    /* Setup our hashtable */
    ssl__ctxs = ghash_create(19,(KEYHASHFUNC)str_hash_code,
                             (KEYCOMPAREFUNC)j_strcmp);

    /* Walk our node and add the created contexts */
    for(cur = xmlnode_get_tag(x, "key"); cur != NULL; 
                    cur = xmlnode_get_nextsibling(cur))
    {
        host = xmlnode_get_attrib(cur, "ip");
        keypath = xmlnode_get_data(cur);

        ctx=SSL_CTX_new(SSLv23_server_method());

#ifndef NO_RSA
        log_debug(ZONE, "Setting temporary RSA callback");
        SSL_CTX_set_tmp_rsa_callback(ctx, _ssl_tmp_rsa_cb);
#endif /* NO_RSA */

        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);

        /* XXX I would like to make this a configurable option */
        /* 
         SSL_CTX_set_timeout(ctx, session_timeout);
         */

        /* Setup the keys and certs */
#ifdef NO_RSA
        if(!SSL_CTX_use_PrivateKey_file(ctx, keypath,SSL_FILETYPE_PEM)) 
        {
            log_debug(ZONE, "SSL Error using Private Key file without RSA");
            SSL_CTX_free(ctx);
            continue;
        }
#else /* NO_RSA */
        if(!SSL_CTX_use_RSAPrivateKey_file(ctx, keypath, SSL_FILETYPE_PEM)) 
        {
            log_debug(ZONE, "SSL Error using Private Key file without RSA");
            SSL_CTX_free(ctx);
            continue;
        }
#endif /* NO_RSA */
        ghash_put(ssl__ctxs, host, ctx);
    }
        
}

ssize_t _mio_ssl_read(mio m, void *buf, size_t count)
{
    return SSL_read((SSL *)m->ssl, (char *)buf, count);
}

ssize_t _mio_ssl_write(mio m, const void *buf, size_t count)
{
    return SSL_write((SSL *)m->ssl, buf, count);    
}

int _mio_ssl_accept(mio m, struct sockaddr * serv_addr, socklen_t *addrlen)
{
    SSL *ssl=NULL;
    SSL_CTX *ctx = NULL;
    int fd;

    log_debug(ZONE, "Accepting new SSL socket for %s", m->ip);
    ctx = ghash_get(ssl__ctxs, m->ip);
    
    fd = accept(m->fd, serv_addr, addrlen);
    SSL_set_fd(ssl, fd);
    SSL_set_accept_state(ssl);
    if(SSL_accept(ssl) <= 0){
        log_debug(ZONE, "SSL Error in SSL_accept call");
        SSL_free(ssl);
        close(fd);
        return -1;
    }

    m->ssl = ssl;

    return fd;
}

int _mio_ssl_connect(mio m, struct sockaddr *serv_addr, socklen_t addrlen)
{

    /* PSEUDO
     I need to actually look this one up, but I assume it's similar to the
       SSL accept stuff.
    */
    SSL *ssl=NULL;
    SSL_CTX *ctx = NULL;
    int fd;

    log_debug(ZONE, "Connecting new SSL socket for %s", m->ip);
    ctx = ghash_get(ssl__ctxs, m->ip);
    
    fd = connect(m->fd, serv_addr, addrlen);
    SSL_set_fd(ssl, fd);
    if(SSL_connect(ssl) <= 0){
        log_debug(ZONE, "SSL Error in SSL_connect call");
        SSL_free(ssl);
        close(fd);
        return -1;
    }

    m->ssl = ssl;

    return fd;
}

#endif /* HAVE_SSL */
