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

#include "jadc2s.h"

#include <fstream>

/* check jadc2s.h for an overview of this codebase */
static int process_conns = 1;

#ifdef WITH_SASL
/* forward declarations */
static int _sasl_canon_user(sasl_conn_t *conn, void *context, const char *in, unsigned inlen, unsigned flags, const char *user_realm, char *out, unsigned out_max, unsigned *out_len);
static int _sasl_proxy_auth_check(sasl_conn_t *conn, void *context, const char *requested_user, unsigned rlen, const char *auth_identity, unsigned alen, const char *def_realm, unsigned urlen, struct propctx *propctx);

/* SASL callbacks */
static sasl_callback_t sasl_callbacks[] = {
    { SASL_CB_CANON_USER, (int (*)())(&_sasl_canon_user), NULL },
    { SASL_CB_PROXY_POLICY, (int (*)())_sasl_proxy_auth_check, NULL},
    { SASL_CB_LIST_END, NULL, NULL }
};

/**
 * callback for cyrus sasl, that stringpres XMPP user ids
 */
static int _sasl_canon_user(sasl_conn_t *conn, void *context, const char *in, unsigned inlen, unsigned flags, const char *user_realm, char *out, unsigned out_max, unsigned *out_len) {
    c2s_t c2s = (c2s_t)context;
    jid user_jid = NULL;
    pool local_pool = NULL;

    /* sanity check */
    if (c2s == NULL) {
	log_debug(ZONE, "_sasl_canon_user called with NULL context");
	return SASL_FAIL;
    }

    /* stringprep the ID */
    local_pool = pool_new();
    user_jid = jid_new(local_pool, c2s->jid_environment, user_realm);
    jid_set(user_jid, in, JID_USER);
    if (user_jid->user == NULL) {
	pool_free(local_pool);
	return SASL_BADPROT;
    }

    /* enough memory? */
    if (j_strlen(user_jid->user) >= out_max) {
	pool_free(local_pool);
	return SASL_BUFOVER;
    }

    /* copy to the output buffer */
    strcpy(out, user_jid->user);
    *out_len = j_strlen(user_jid->user);
    pool_free(local_pool);
    user_jid = NULL;

    return SASL_OK;
}

/**
 * callback for cyrus sasl, that checks if a user is allowed to authenticate as another id
 */
static int _sasl_proxy_auth_check(sasl_conn_t *conn, void *context, const char *requested_user, unsigned rlen, const char *auth_identity, unsigned alen, const char *def_realm, unsigned urlen, struct propctx *propctx) {
    c2s_t c2s = (c2s_t)context;
    pool local_pool = NULL;
    jid auth_jid = NULL;
    jid authz_jid = NULL;
    int i = 0;
    int has_admin_rights = 0;

    /* sanity check */
    if (c2s == NULL) {
	log_debug(ZONE, "_sasl_proxy_auth_check called with NULL context");
	return SASL_FAIL;
    }

    /* more sanity checks */
    if (requested_user == NULL || auth_identity == NULL || def_realm == NULL) {
	c2s->log->level(LOG_ERR) << "Internal error: illegal NULL value passed to _sasl_proxy_auth_check as " << (requested_user == NULL ? "requested_user" : auth_identity == NULL ? "auth_identity" : "def_realm");
	return SASL_FAIL;
    }

    /* prepare auth and authz jid */
    local_pool = pool_new();
    if (strchr(requested_user, '@') == NULL) {
	authz_jid = jid_new(local_pool, c2s->jid_environment, def_realm);
	if (authz_jid == NULL) {
	    c2s->log->level(LOG_ERR) << "Internal error: could not initialize authz_jid with default realm " << def_realm;
	    pool_free(local_pool);
	    return SASL_FAIL;
	}
	jid_set(authz_jid, requested_user, JID_USER);

	if (authz_jid->user == NULL || authz_jid->server == NULL || authz_jid->resource != NULL) {
	    c2s->log->level(LOG_ERR) << "Internal error: " << requested_user << "@" << def_realm << " initialized authz_jid to " << jid_full(authz_jid);
	    pool_free(local_pool);
	    return SASL_FAIL;
	}
    } else {
	authz_jid = jid_new(local_pool, c2s->jid_environment, requested_user);
	if (authz_jid == NULL || authz_jid->user == NULL || authz_jid->server == NULL || authz_jid->resource != NULL) {
	    c2s->log->level(LOG_ERR) << "Internal error: " << requested_user << " initialized authz_jid to " << (authz_jid == NULL ? "NULL" : jid_full(authz_jid));
	    pool_free(local_pool);
	    return SASL_FAIL;
	}
    }
    if (strchr(auth_identity, '@') == NULL) {
	auth_jid = jid_new(local_pool, c2s->jid_environment, def_realm);
	if (auth_jid == NULL) {
	    c2s->log->level(LOG_ERR) << "Internal error: could not initialize auth_jid with default realm " << def_realm;
	    pool_free(local_pool);
	    return SASL_FAIL;
	}
	jid_set (auth_jid, auth_identity, JID_USER);

	if (auth_jid->user == NULL || auth_jid->server == NULL || auth_jid->resource != NULL) {
	    c2s->log->level(LOG_ERR) << "Internal error: " << auth_identity << "@" << def_realm << " initialized auth_jid to " << jid_full(auth_jid);
	    pool_free(local_pool);
	    return SASL_FAIL;
	}
    } else {
	auth_jid = jid_new(local_pool, c2s->jid_environment, auth_identity);
	if (auth_jid == NULL || auth_jid->user == NULL || auth_jid->server == NULL || auth_jid->resource != NULL) {
	    c2s->log->level(LOG_ERR) << "Internal error: " << auth_identity << " initialized auth_jid to " << (auth_jid == NULL ? "NULL" : jid_full(auth_jid));
	    pool_free(local_pool);
	    return SASL_FAIL;
	}
    }

    /* a user is always allowed to authenticate as himself */
    if (jid_cmp(authz_jid, auth_jid) == 0) {
	log_debug(ZONE, "user %s authorized as himself", jid_full(auth_jid));
	pool_free(local_pool);
	return SASL_OK;
    }

    /* check if the auth_jid is allowed to authorize as authz_jid */
    for (i=0; c2s->sasl_admin != NULL && i < c2s->sasl_admin->nvalues; i++) {
	jid auth_as_jid = NULL;
	jid config_jid = jid_new(local_pool, c2s->jid_environment, c2s->sasl_admin->values[i]);

	/* as there a valid JID? */
	if (config_jid == NULL) {
	    c2s->log->level(LOG_WARNING) << "invalid configuration option <authorization><admin>" << c2s->sasl_admin->values[i] << "</admin></authorization>";
	    continue;
	}

	/* is this configuration option for the authenticated user? */
	if (jid_cmpx(config_jid, auth_jid, JID_USER|JID_SERVER) != 0) {
	    continue; /* no, other user */
	}

	/* configured JIDs without resource have access to authorize as anybody */
	if (config_jid->resource == NULL) {
	    c2s->log->level(LOG_NOTICE) << "User " << jid_full(auth_jid) << " (super admin) has been authorized as user " << jid_full(authz_jid);
	    pool_free(local_pool);
	    return SASL_OK;
	}

	/* it might not be for the requested user, but the user at least has some rights to authenticate as someone else */
	has_admin_rights = 1;

	/* what authz_jid values are allowed using this config option? */
	auth_as_jid = jid_new(local_pool, c2s->jid_environment, config_jid->resource);
	if (auth_as_jid == NULL || auth_as_jid->resource != NULL) {
	    c2s->log->level(LOG_WARNING) << "invalid configuration option <authorization><admin>" << c2s->sasl_admin->values[i] << "</admin></authorization> (resource invalid)";
	    continue;
	}

	/* authorized for a full domain? */
	if (auth_as_jid->user == NULL) {
	    if (jid_cmpx(auth_as_jid, authz_jid, JID_SERVER) == 0) {
		c2s->log->level(LOG_NOTICE) << "User " << jid_full(auth_jid) << " (domain admin) has been authorized as user " << jid_full(authz_jid);
		pool_free(local_pool);
		return SASL_OK;
	    }
	} else {
	    if (jid_cmp(auth_as_jid, authz_jid) == 0) {
		c2s->log->level(LOG_NOTICE) << "User " << jid_full(auth_jid) << " (user admin) has been authorized as user " << jid_full(authz_jid);
		pool_free(local_pool);
		return SASL_OK;
	    }
	}
    }

    c2s->log->level(LOG_WARNING) << "Denied " << (has_admin_rights ? "admin" : "non-admin") << " user " << jid_full(auth_jid) << " to authorize as user " << jid_full(authz_jid);

    pool_free(local_pool);
    return SASL_NOAUTHZ;
}
#endif

/***
* Iterate over the bad conns list and reset people that are ok
* @param c2s The c2s instance to process from
*/
static void check_karma(c2s_t c2s) {
    bad_conn_t cur, next;
    time_t start;

    time(&start);

    cur = c2s->bad_conns;
    while ( (cur != NULL) && (cur->last < start) )
    {
        next = cur->next;
        /* Let them read again */
        mio_read(c2s->mio, cur->c->fd);
        /* cleanup and move on in the list */
        free(cur);

        cur = next;
    }

    /* update the pointer to the first bad connection */
    c2s->bad_conns = cur;
    if (c2s->bad_conns == NULL)
    {
	/* XXX Make this a config option? */
	c2s->timeout = c2s->default_timeout;
    }
}

static void usage(void) {
    fputs(
	"This is version " VERSION " of jadc2s\n\n"
#ifdef USE_SSL
	"SSL/TLS is enabled in this build.\n"
#endif
#ifdef WITH_SASL
	"SASL is enabled in this build.\n"
#endif
	"\n"
        "Usage: jadc2s <options>\n"
        "Options are:\n"
	"   -h              output this help message\n"
        "   -c <config>     config file to use\n"
	"                   [default: " CONFIG_DIR "/jadc2s.xml]\n"
	"   -r <randdev>    device to read randomization seed from\n"
        "   -o key=value    override config file property\n"
        "   -b              run in background\n", stdout);
}

/* 
 * Handle signals that would stop us nicely
 */
static void onSignal(int signal) {
    /* Just tell ourselves to stop process */
    process_conns = 0;
}

static int ignore_term_signals(void) {
    /* !!! the list of signals to ignore -- needs to be reviewed */
    int sig[] = {SIGHUP, SIGQUIT, SIGTSTP, SIGTTIN, SIGTTOU};

    int num_sigs = (sizeof sig) / (sizeof sig[0]);
    int i;
    struct sigaction dae_action;
    
    dae_action.sa_handler = SIG_IGN;
    sigemptyset(&(dae_action.sa_mask));
    dae_action.sa_flags = 0;
    
    for (i = 0; i < num_sigs; ++i)
    	if (sigaction(sig[i], &dae_action, NULL) == -1) return -1;
    
    return 0;
}

static int daemonize(void) {
    pid_t pid;
    int i;

    fprintf(stderr, "preparing to run in daemon mode ...\n");
    
    if ((pid = fork()) != 0)
       exit(0);

    /* become session leader */
    setsid();

    /* ignore the signals we want */
    ignore_term_signals();
    
    if ((pid = fork()) != 0)
       exit(0);

    /* !!! could change to our working directory */
    // chdir("/"); 

    umask(0);

    /* close open descriptors */
    for (i=0; i < MAXFD; ++i)
       close(i);

    return 0;
}


/* although this is our main and it's an all-in-one right now,
 * it's done in a way that would make it quite easy to thread, 
 * customize, or integrate with another codebase
 */
int main(int argc, char **argv) {
    c2s_t c2s;
    time_t last_log, last_pending, last_jid_clean, now;
    char optchar;
    int config_loaded = 0;
    int i, fd;
    char *rand_dev = NULL;
    unsigned int rand_seed = 0;
    int sasl_result = 0;

    signal(SIGINT, onSignal);
    signal(SIGPIPE, SIG_IGN);
    
    /* set up our c2s global stuff */
    c2s = (c2s_t)malloc(sizeof(struct c2s_st));
    memset(c2s, 0, sizeof(struct c2s_st));

    /* create environment for jid preparation */
    c2s->jid_environment = jid_new_environment();

    /* set default for rand_dev */
    rand_dev = strdup("/dev/urandom");

    /* load our config */
    c2s->config = config_new();

    /* cmdline parsing */
    while((optchar = getopt(argc, argv, "c:r:bh?")) >= 0)
    {
        switch(optchar)
        {
            case 'h': case '?':
                usage();
                return 1;
	    case 'r':
		free(rand_dev);
		rand_dev = strdup(optarg);
		break;
            case 'c':
                if(!config_load(c2s->config, optarg))
                    config_loaded++;
                break;
    	    case 'b':
                /* !!! needs testing */
                /* !!! should this be a cmdline option, or in the config? */
                daemonize();
                break;	       
        }
    }

    if(!config_loaded && config_load(c2s->config, CONFIG_DIR "/jadc2s.xml"))
    {
        fprintf(stderr, "no config loaded, aborting\n");
        usage();
        return 1;
    }

    /* inbuilt defaults and config file options */
    /* !!! config options for these? */
    c2s->connection_rates = new std::map<std::string, connection_rate_t>;
    c2s->pending = new std::map<std::string, conn_t>;
    c2s->bad_conns = NULL;
    c2s->timeout = c2s->default_timeout;

    /* conn setup */
    c2s->max_fds = j_atoi(config_get_one(c2s->config, "io.max_fds", 0), 1023);
    c2s->mio = mio_new(c2s->max_fds);
    c2s->conns = (struct conn_st *) malloc(sizeof(struct conn_st) * c2s->max_fds);
    memset(c2s->conns, 0, sizeof(struct conn_st) * c2s->max_fds);
    for(i = 0; i < c2s->max_fds; i++)
        c2s->conns[i].fd = -1;      /* -1 == unused */

    /* nad cache */
    c2s->nads = nad_cache_new();

    /* session manager */
    c2s->sm_host = config_get_one(c2s->config, "sm.host", 0);
    c2s->sm_port = j_atoi(config_get_one(c2s->config, "sm.port", 0), 0);
    c2s->sm_id = config_get_one(c2s->config, "sm.id", 0);
    c2s->sm_secret = config_get_one(c2s->config, "sm.secret", 0);

    c2s->connection_rate_times =
        j_atoi(config_get_one(c2s->config, "io.connection_limits.connects", 0), 0);
    c2s->connection_rate_seconds =
        j_atoi(config_get_one(c2s->config, "io.connection_limits.seconds", 0), 0);
    
    /* XXX Change before release */
    c2s->local_id = config_get(c2s->config,"local.id");
    c2s->local_alias = config_get(c2s->config,"local.alias");
    c2s->local_noregister = config_get(c2s->config,"local.noregister");
    c2s->local_nolegacyauth = config_get(c2s->config,"local.nolegacyauth");
    c2s->local_ip = config_get_one(c2s->config, "local.ip", 0);
    c2s->local_port = j_atoi(config_get_one(c2s->config, "local.port", 0), 5222);
    c2s->local_statfile = config_get_one(c2s->config, "local.statfile", 0);
    c2s->http_forward = config_get_one(c2s->config, "local.httpforward", 0);
#ifdef USE_SSL
    c2s->local_sslport = j_atoi(config_get_one(c2s->config, "local.ssl.port", 0), 5223);
    c2s->pemfile = config_get_one(c2s->config, "local.ssl.pemfile", 0);
    c2s->ciphers = config_get_one(c2s->config, "local.ssl.ciphers", 0);
    
    c2s->ssl_enable_workarounds = (config_get_one(c2s->config, "local.ssl.enable_workarounds", 0) != NULL);
    c2s->ssl_no_ssl_v2 = (config_get_one(c2s->config, "local.ssl.no_ssl_v2", 0) != NULL);
    c2s->ssl_no_ssl_v3 = (config_get_one(c2s->config, "local.ssl.no_ssl_v3", 0) != NULL);
    c2s->ssl_no_tls_v1 = (config_get_one(c2s->config, "local.ssl.no_tls_v1", 0) != NULL);
    c2s->ssl_enable_autodetect = (config_get_one(c2s->config, "local.ssl.enable_autodetect", 0) != NULL);
#endif
    c2s->iplog = (config_get_one(c2s->config, "io.iplog", 0) != NULL);
    c2s->default_timeout = j_atoi(config_get_one(c2s->config, "io.authtimeout", 0), 15);

    /* require some things */
    if(c2s->sm_host == NULL) {
	fprintf(stderr, "Need the hostname where to find the router in the configuration\n");
	usage();		/* XXX usage isn't really helpful for this */
	return 1;
    }
    if(c2s->sm_port == 0) {
	fprintf(stderr, "Need the port number of the router in the configuration\n");
	usage();		/* XXX usage isn't really helpful for this */
	return 1;
    }
    if(c2s->sm_id == NULL) {
	fprintf(stderr, "Need our ID on the router in the configuration\n");
	usage();		/* XXX usage isn't really helpful for this */
	return 1;
    }
    if(c2s->sm_secret == NULL) {
	fprintf(stderr, "Need the secret for the router in the configuration\n");
	usage();		/* XXX usage isn't really helpful for this */
	return 1;
    }
    if(c2s->local_id == NULL) {
	fprintf(stderr, "Need our domain(s) for which connections should be accepted in the config\n");
	usage();		/* XXX usage isn't really helpful for this */
	return 1;
    }

    /* authentication configuration stuff */
    c2s->sasl_enabled = config_get_one(c2s->config, "authentication", 0) == NULL ? 0 : 1;
    if (c2s->sasl_enabled != 0) {
	c2s->sasl_jep0078 = config_get_one(c2s->config, "authentication.legacyauth", 0) == NULL ? 0 : 1;
	c2s->sasl_appname = config_get_one(c2s->config, "authentication.appname", 0);
	if (c2s->sasl_appname == NULL) {
	    c2s->sasl_appname = PACKAGE;
	}
	c2s->sasl_service = config_get_one(c2s->config, "authentication.service", 0);
	if (c2s->sasl_service == NULL) {
	    c2s->sasl_service = "xmpp";
	}
	c2s->sasl_fqdn = config_get_one(c2s->config, "authentication.fqdn", 0);
	c2s->sasl_defaultrealm = config_get_one(c2s->config, "authentication.defaultrealm", 0);
	c2s->sasl_min_ssf = j_atoi(config_get_one(c2s->config, "authentication.minssf", 0), 0);
	c2s->sasl_max_ssf = (unsigned)j_atoi(config_get_one(c2s->config, "authentication.maxssf", 0), -1);
	c2s->sasl_noseclayer = config_get_one(c2s->config, "authentication.noseclayer", 0) == NULL ? 0 : 1;
	c2s->sasl_sec_flags = (unsigned)j_atoi(config_get_one(c2s->config, "authentication.secflags", 0), SASL_SEC_NOANONYMOUS);
	c2s->sasl_admin = config_get(c2s->config, "authentication.admin");
    }

    /* start logging */
    c2s->log = new logging(c2s->sm_id);
    c2s->log->level(LOG_NOTICE) << "starting up as " << c2s->sm_id;

    /* seed the random number generator */
    fd = open(rand_dev, O_RDONLY|O_NOCTTY);
    if (fd != -1) {
	read(fd, &rand_seed, sizeof(rand_seed));
	close(fd);
    }
    if (rand_seed == 0) {
	c2s->log->level(LOG_NOTICE) << "could not seed random number generator from " << rand_dev << " - using time";
	rand_seed = time(NULL);
    }
    srand(rand_seed);
    free(rand_dev);

    /* first, make sure we can connect to our sm */
    if (!connect_new(c2s)) {
	c2s->log->level(LOG_ERR) << "Unable to connect to sm!";
        exit(1);
    }

    /* only bind the unencrypted port if we have a real port number for it */
    if (c2s->local_port > 0) {
        /* then make sure we can listen */
        if (mio_listen(c2s->mio, c2s->local_port, c2s->local_ip, client_io, (void*)c2s) < 0) {
	    c2s->log->level(LOG_ERR) << "failed to listen on port " << c2s->local_port << "!";
            return 1;
        }

	c2s->log->level(LOG_NOTICE) << "listening for client connections on port " << c2s->local_port;
    }

#ifdef USE_SSL
    /* get the SSL port all set up */
// XXX    if(c2s->local_sslport == 0 || c2s->pemfile == NULL)
    if (c2s->pemfile == NULL)
	c2s->log->level(LOG_WARNING) << "SSL/TLS pem file not specified, SSL/TLS disabled";
    else {
        /* init the OpenSSL library */
        OpenSSL_add_ssl_algorithms();
        SSL_load_error_strings();
        c2s->ssl_ctx = SSL_CTX_new(SSLv23_server_method());

	if (c2s->ssl_ctx == NULL) {
	    c2s->log->level(LOG_ERR) << "failed to initialize SSL/TLS library";
	    c2s->log->level(LOG_ERR).ssl_errors();
	    return 1;
	}

        /* if these fail, we keep the context hanging around, because we free it at shutdown */
        if (SSL_CTX_use_certificate_file(c2s->ssl_ctx, c2s->pemfile, SSL_FILETYPE_PEM) != 1) {
	    c2s->log->level(LOG_WARNING) << "failed to load certificate from " << c2s->pemfile << ", SSL/TLS disabled";
	    c2s->log->level(LOG_WARNING).ssl_errors();
	    c2s->ssl_ctx = NULL;
	} else if (SSL_CTX_use_PrivateKey_file(c2s->ssl_ctx, c2s->pemfile, SSL_FILETYPE_PEM) != 1) {
	    c2s->log->level(LOG_WARNING) << "failed to load private key from " << c2s->pemfile << ", SSL/TLS disabled";
	    c2s->log->level(LOG_WARNING).ssl_errors();
	    c2s->ssl_ctx = NULL;
	} else {
            if (!SSL_CTX_check_private_key(c2s->ssl_ctx)) {
		c2s->log->level(LOG_WARNING) << "private key does not match certificate public key, SSL/TLS disabled";
		c2s->log->level(LOG_WARNING).ssl_errors();
		c2s->ssl_ctx = NULL;
	    } else {
		if (c2s->ciphers != NULL && !SSL_CTX_set_cipher_list(c2s->ssl_ctx, c2s->ciphers)) {
		    c2s->log->level(LOG_ERR) << "non of the configured ciphers could be enabled, SSL/TLS disabled";
		    c2s->log->level(LOG_ERR).ssl_errors();
		    c2s->ssl_ctx = NULL;
		}
		if (c2s->local_sslport != 0 ) {
		    if (mio_listen(c2s->mio, c2s->local_sslport, c2s->local_ip, client_io, (void*)c2s) < 0)
			c2s->log->level(LOG_ERR) << "failed to listen on port " << c2s->local_sslport << "!";
		    else
			c2s->log->level(LOG_NOTICE) << "listening for SSL/TLS client connections on port " << c2s->local_sslport;
		}
	    }
        }

	/* enable workarounds for different SSL client bugs or disable
	 * some versions of SSL/TLS */
	if (c2s->ssl_enable_workarounds)
	    SSL_CTX_set_options(c2s->ssl_ctx, SSL_OP_ALL);
	if (c2s->ssl_no_ssl_v2)
	    SSL_CTX_set_options(c2s->ssl_ctx, SSL_OP_NO_SSLv2);
	if (c2s->ssl_no_ssl_v3)
	    SSL_CTX_set_options(c2s->ssl_ctx, SSL_OP_NO_SSLv3);
	if (c2s->ssl_no_tls_v1)
	    SSL_CTX_set_options(c2s->ssl_ctx, SSL_OP_NO_TLSv1);
    }
#endif

#ifdef WITH_SASL
    if (c2s->sasl_enabled != 0) {
	int i = 0;
	for (i=0; sasl_callbacks[i].id!=SASL_CB_LIST_END; i++) {
	    log_debug(ZONE, "callback init for %i", i);
	    sasl_callbacks[i].context = (void*)c2s;
	}
	sasl_result = sasl_server_init(sasl_callbacks, c2s->sasl_appname);
	if (sasl_result != SASL_OK) {
	    c2s->log->level(LOG_ERR) << "initialization of SASL library failed: " << sasl_result;
	    exit(1);
	}
	c2s->log->level(LOG_NOTICE) << "SASL authentication enabled";
    } else {
	c2s->log->level(LOG_NOTICE) << "SASL authentication disabled";
    }

#else /* WITH(out)_SASL */
    if (c2s->sasl_enabled != 0) {
	c2s->log->level(LOG_ERR) << "SASL requested in configuration file, but " PACKAGE " compiled without SASL support.";
	exit(1);
    }
#endif /* WITH(out)_SASL */

    /* just a matter of processing socket events now */
    last_jid_clean = last_pending = last_log = time(NULL);
    while(process_conns)
    {
        mio_run(c2s->mio, c2s->timeout);

        /* log this no more than once per minute */
        if ((time(NULL) - last_log) > 60) {
	    c2s->log->level(LOG_NOTICE) << "current number of clients: " << c2s->num_clients;
            if(c2s->local_statfile != NULL) {
		std::ofstream statfile(c2s->local_statfile);
		if (statfile)
		    statfile << c2s->num_clients;
            }
            last_log = time(NULL);
        }

        /* !!! XXX Should these be configurable cleanup times? */
        /* every so often check for timed out pending conns */
        if((time(&now) - last_pending) > 15) {
	    std::map<std::string, conn_t>::iterator p;
	    for (p = c2s->pending->begin(); p != c2s->pending->end(); ++p) {
		if (now - p->second->start > c2s->timeout && p->second->fd != -1) {
		    conn_close(p->second, STREAM_ERR_TIMEOUT, "You have not authenticated in time");
		}
	    }
            last_pending = time(NULL);
        }

	/* cleanup the stringprep caches */
	if ((time(NULL) - last_jid_clean) > 60) {
	    jid_clean_cache(c2s->jid_environment);
	}

        /* !!! XXX Move this in here for optimization? */
        connection_rate_cleanup(c2s);

        /* XXX This still feels odd having more stuff in here */
        check_karma(c2s);
    }

    /* TODO: Notify sessionmanager about shutdown */
    c2s->log->level(LOG_NOTICE) << "shutting down";

    /* close client connections */
    for(i = 0; i < c2s->max_fds; i++)
	if (c2s->conns[i].fd != -1 && c2s->conns[i].fd != c2s->sm->fd) 
	    conn_close(&c2s->conns[i], STREAM_ERR_SYSTEM_SHUTDOWN, "shutting down jadc2s");

    /* close session manager connection */
    c2s->shutting_down = 1;
    conn_close(c2s->sm, NULL, NULL);

    /* exiting, clean up */
    mio_free(c2s->mio);
    delete c2s->connection_rates;
    delete c2s->pending;
    free(c2s->conns);
    nad_cache_free(c2s->nads);
    if (c2s->log != NULL)
	delete c2s->log;
    c2s->log = NULL;
#ifdef USE_SSL
    SSL_CTX_free(c2s->ssl_ctx);
#endif
    delete c2s->config;
    free(c2s);

    pool_stat(1);

    return 0;
}

/* spit out debug output */
void debug_log(char *file, int line, const char *msgfmt, ...) {
    // debug logging still has to be moved to be stream based, just removing debug_log for now to get rid of snprintf/vsnprintf
}
