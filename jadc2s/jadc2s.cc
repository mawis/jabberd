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
#include <stdexcept>

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
    /* sanity check */
    if (context == NULL) {
	DBG("_sasl_canon_user called with NULL context");
	return SASL_FAIL;
    }
    xmppd::pointer<c2s_st> c2s = *static_cast< xmppd::pointer<c2s_st>* >(context);

    /* stringprep the ID */
    xmppd::pointer<xmppd::jid> user_jid = new xmppd::jid(c2s->used_jid_environment, user_realm);
    user_jid->set_node(in);
    if (!user_jid->has_node()) {
	return SASL_BADPROT;
    }

    /* enough memory? */
    std::string preped_user = user_jid->get_node(); // we have to count bytes, not characters here
    if (preped_user.length() >= out_max) {
	return SASL_BUFOVER;
    }

    /* copy to the output buffer */
    strcpy(out, preped_user.c_str());
    *out_len = preped_user.length();

    return SASL_OK;
}

/**
 * callback for cyrus sasl, that checks if a user is allowed to authenticate as another id
 */
static int _sasl_proxy_auth_check(sasl_conn_t *conn, void *context, const char *requested_user, unsigned rlen, const char *auth_identity, unsigned alen, const char *def_realm, unsigned urlen, struct propctx *propctx) {
    xmppd::pointer<xmppd::jid> auth_jid = NULL;
    xmppd::pointer<xmppd::jid> authz_jid = NULL;
    int i = 0;
    int has_admin_rights = 0;

    /* sanity check */
    if (context == NULL) {
	DBG("_sasl_proxy_auth_check called with NULL context");
	return SASL_FAIL;
    }
    xmppd::pointer<c2s_st> c2s = *static_cast< xmppd::pointer<c2s_st>* >(context);

    /* more sanity checks */
    if (requested_user == NULL || auth_identity == NULL || def_realm == NULL) {
	c2s->log->level(LOG_ERR) << "Internal error: illegal NULL value passed to _sasl_proxy_auth_check as " << (requested_user == NULL ? "requested_user" : auth_identity == NULL ? "auth_identity" : "def_realm");
	return SASL_FAIL;
    }

    /* prepare auth and authz jid */
    if (strchr(requested_user, '@') == NULL) {
	try {
	    authz_jid = new xmppd::jid(c2s->used_jid_environment, def_realm);
	} catch (Glib::ustring msg) {
	    c2s->log->level(LOG_ERR) << "Internal error: could not initialize authz_jid with default realm " << def_realm << ": " << msg;
	    return SASL_FAIL;
	}
	authz_jid->set_node(requested_user);

	if (!authz_jid->has_node() || !authz_jid->has_domain() || authz_jid->has_resource()) {
	    c2s->log->level(LOG_ERR) << "Internal error: " << requested_user << "@" << def_realm << " initialized authz_jid to " << authz_jid->full();
	    return SASL_FAIL;
	}
    } else {
	try {
	    authz_jid = new xmppd::jid(c2s->used_jid_environment, requested_user);
	} catch (Glib::ustring msg) {
	    c2s->log->level(LOG_ERR) << "Internal error: " << requested_user << " initialized authz_jid to NULL: " << msg;
	    return SASL_FAIL;
	}
	if (!authz_jid->has_node() || !authz_jid->has_domain() || authz_jid->has_resource()) {
	    c2s->log->level(LOG_ERR) << "Internal error: " << requested_user << " initialized authz_jid to " << authz_jid->full();
	    return SASL_FAIL;
	}
    }
    if (strchr(auth_identity, '@') == NULL) {
	try {
	    auth_jid = new xmppd::jid(c2s->used_jid_environment, def_realm);
	} catch (Glib::ustring msg) {
	    c2s->log->level(LOG_ERR) << "Internal error: could not initialize auth_jid with default realm " << def_realm << ": " << msg;
	    return SASL_FAIL;
	}
	auth_jid->set_node(auth_identity);

	if (!auth_jid->has_node() || !auth_jid->has_domain() || auth_jid->has_resource()) {
	    c2s->log->level(LOG_ERR) << "Internal error: " << auth_identity << "@" << def_realm << " initialized auth_jid to " << auth_jid->full();
	    return SASL_FAIL;
	}
    } else {
	try {
	    auth_jid = new xmppd::jid(c2s->used_jid_environment, auth_identity);
	} catch (Glib::ustring msg) {
	    c2s->log->level(LOG_ERR) << "Internal error: " << auth_identity << " initialized auth_jid to NULL: " << msg;
	    return SASL_FAIL;
	}
	if (!auth_jid->has_node() || !auth_jid->has_domain() || auth_jid->has_resource()) {
	    c2s->log->level(LOG_ERR) << "Internal error: " << auth_identity << " initialized auth_jid to " << auth_jid->full();
	    return SASL_FAIL;
	}
    }

    /* a user is always allowed to authenticate as himself */
    if (*authz_jid == *auth_jid) {
	DBG("user " << auth_jid->full() << "authorized as himself");
	return SASL_OK;
    }

    /* check if the auth_jid is allowed to authorize as authz_jid */
    std::list<xmppd::configuration_entry>::iterator p;
    for (p = c2s->sasl_admin.begin(); p!=c2s->sasl_admin.end(); ++p) {
	xmppd::pointer<xmppd::jid> auth_as_jid = NULL;
	xmppd::pointer<xmppd::jid> config_jid = NULL;
	try {
	    config_jid = new xmppd::jid(c2s->used_jid_environment, p->value);
	} catch (Glib::ustring msg) {
	    /* as there a valid JID? */
	    c2s->log->level(LOG_WARNING) << "invalid configuration option <authorization><admin>" << p->value << "</admin></authorization>";
	    continue;
	}

	/* is this configuration option for the authenticated user? */
	if (!config_jid->cmpx(*auth_jid)) {
	    continue; /* no, other user */
	}

	/* configured JIDs without resource have access to authorize as anybody */
	if (!config_jid->has_resource()) {
	    c2s->log->level(LOG_NOTICE) << "User " << auth_jid->full() << " (super admin) has been authorized as user " << authz_jid->full();
	    return SASL_OK;
	}

	/* it might not be for the requested user, but the user at least has some rights to authenticate as someone else */
	has_admin_rights = 1;

	/* what authz_jid values are allowed using this config option? */
	try {
	    auth_as_jid = new xmppd::jid(c2s->used_jid_environment, config_jid->get_resource());
	} catch (Glib::ustring msg) {
	    c2s->log->level(LOG_WARNING) << "invalid configuration option <authorization><admin>" << p->value << "</admin></authorization> (resource invalid)";
	    continue;
	}
	if (auth_as_jid->has_resource()) {
	    c2s->log->level(LOG_WARNING) << "invalid configuration option <authorization><admin>" << p->value << "</admin></authorization> (resource invalid)";
	    continue;
	}

	/* authorized for a full domain? */
	if (!auth_as_jid->has_node()) {
	    if (auth_as_jid->cmpx(*authz_jid)) {
		c2s->log->level(LOG_NOTICE) << "User " << auth_jid->full() << " (domain admin) has been authorized as user " << authz_jid->full();
		return SASL_OK;
	    }
	} else {
	    if (auth_as_jid->cmpx(*authz_jid)) {
		c2s->log->level(LOG_NOTICE) << "User " << auth_jid->full() << " (user admin) has been authorized as user " << authz_jid->full();
		return SASL_OK;
	    }
	}
    }

    c2s->log->level(LOG_WARNING) << "Denied " << (has_admin_rights ? "admin" : "non-admin") << " user " << auth_jid->full() << " to authorize as user " << authz_jid->full();

    return SASL_NOAUTHZ;
}
#endif

/***
* Iterate over the bad conns list and reset people that are ok
* @param c2s The c2s instance to process from
*/
static void check_karma(xmppd::pointer<c2s_st> c2s) {
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
	delete cur;

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
    std::cout <<
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
        "   -b              run in background" << std::endl;
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

c2s_st::c2s_st(int argc, char* const* argv) : mio(NULL), shutting_down(0), local_port(0),
#ifdef USE_SSL
    local_sslport(0), ssl_no_ssl_v2(0), ssl_no_ssl_v3(0), ssl_no_tls_v1(0),
    ssl_enable_workarounds(0), ssl_enable_autodetect(0), ssl_ctx(NULL), tls_required(0),
#endif
    config(NULL), nads(NULL), connection_rate_times(0), connection_rate_seconds(0),
    bad_conns(NULL), bad_conns_tail(NULL), timeout(0), default_timeout(0),
    max_fds(0), num_clients(0), sm(NULL), rand_dev("/dev/urandom"), config_loaded(false)
{
    DBG("creating c2s_st instance");

    // parse commandline options
    parse_commandline(argc, argv);

    // configuration may have been loaded while parsing the commandline, if not: load now
    // START OLDCODE
    if (!config_loaded) {
    // END OLDCODE
        config = new xmppd::configuration(CONFIG_DIR "/jadc2s.xml");
    }

    // set configuration default values
    std::ostringstream sasl_sec_noanonymous;
    sasl_sec_noanonymous << SASL_SEC_NOANONYMOUS;

    config->set_default("authentication.appname", PACKAGE);
    config->set_default("authentication.maxssf", "-1");
    config->set_default("authentication.minssf", "0");
    config->set_default("authentication.secflags", sasl_sec_noanonymous.str());
    config->set_default("authentication.service", "xmpp");
    config->set_default("io.authtimeout", "15");
    config->set_default("io.connection_limits.connects", "0");
    config->set_default("io.connection_limits.seconds", "0");
    config->set_default("io.max_bps", "1024");
    config->set_default("io.max_fds", "1023");
    config->set_default("local.port", "5222");
    config->set_default("local.ssl.port", "5223");
    config->set_default("sm.retries", "5");

}

/**
 * process the configuration settings
 *
 * @param xptr_to_self this is ugly - here a managed pointer to the c2s instance is passed - needed to pass it on
 */
void c2s_st::configurate(xmppd::pointer<c2s_st> xptr_to_self) {
    max_fds = config->get_integer("io.max_fds");
    // START OLDCODE
    /* conn setup */
    mio = mio_new(max_fds);
    // END OLDCODE

    // create a connection instance for each possible connection
    conns.resize(max_fds);
    for (int i=0; i < max_fds; i++) {
	conns[i] = new conn_st(xptr_to_self);
    }
    DBG("connections created");

    // START OLDCODE
    /* nad cache */
    nads = nad_cache_new();
    DBG("nad_cache created");
    // END OLDCODE

    /* session manager */
    try {
	sm_host = config->get_string("sm.host");
    } catch (Glib::ustring) {
	throw std::invalid_argument("sm.host not set correctly in configuration");
    }
    try {
	sm_port = config->get_integer("sm.port");
    } catch (Glib::ustring) {
	throw std::invalid_argument("sm.port not set correctly in configuration");
    }
    try {
	sm_id = config->get_string("sm.id");
    } catch (Glib::ustring) {
	throw std::invalid_argument("sm.id not set correctly in configuration");
    }
    try {
	sm_secret = config->get_string("sm.secret");
    } catch (Glib::ustring) {
	throw std::invalid_argument("sm.secret not set correctly in configuration");
    }
    DBG("read connect settings to the Jabber server");

    try {
	connection_rate_times = config->get_integer("io.connection_limits.connects");
    } catch (Glib::ustring) {
	throw std::invalid_argument("Problem with the io.connection_limits.connects setting");
    }
    try {
	connection_rate_seconds = config->get_integer("io.connection_limits.seconds");
    } catch (Glib::ustring) {
	throw std::invalid_argument("Problem with the io.connection_limits.seconds setting");
    }

    if (config->find("local.id") != config->end())
	local_id = (*config)["local.id"];
    if (config->find("local.alias") != config->end())
	local_alias = (*config)["local.alias"];
    if (config->find("local.noregister") != config->end())
	local_noregister = (*config)["local.noregister"];
    if (config->find("local.nolegacyauth") != config->end())
	local_nolegacyauth = (*config)["local.nolegacyauth"];

    try {
	local_ip = config->get_string("local.ip");
    } catch (Glib::ustring) {
	DBG("No local.ip");
    }
    try {
	local_port = config->get_integer("local.port");
    } catch (Glib::ustring) {
	throw std::invalid_argument("Problem with the local.port setting");
    }
    try {
	local_statfile = config->get_string("local.statfile");
    } catch (Glib::ustring) {
	DBG("No local.statfile");
    }
    try {
	http_forward = config->get_string("local.httpforward");
    } catch (Glib::ustring) {
	DBG("No local.httpforward");
    }
   
#ifdef USE_SSL
    // get SSL settings
    try {
	local_sslport = config->get_integer("local.ssl.port");
    } catch (Glib::ustring) {
	DBG("No local.ssl.port");
    }
    try {
	pemfile = config->get_string("local.ssl.pemfile");
    } catch (Glib::ustring) {
	DBG("No local.ssl.pemfile");
    }
    try {
	ciphers = config->get_string("local.ssl.ciphers");
    } catch (Glib::ustring) {
	DBG("No local.ssl.ciphers");
    }
  
    ssl_enable_workarounds = config->find("local.ssl.enable_workarounds") != config->end();
    ssl_no_ssl_v2 = config->find("local.ssl.no_ssl_v2") != config->end();
    ssl_no_ssl_v3 = config->find("local.ssl.no_ssl_v3") != config->end();
    ssl_no_tls_v1 = config->find("local.ssl.no_tls_v1") != config->end();
    ssl_enable_autodetect = config->find("local.ssl.enable_autodetect") != config->end();
#endif

    iplog = config->find("io.iplog") != config->end();
    try {
	timeout = default_timeout = config->get_integer("io.authtimeout");
    } catch (Glib::ustring) {
	throw std::invalid_argument("Problem with the io.authtimeout setting");
    }

    /* require some things */
    if (sm_host.length() == 0) {
	throw Glib::ustring("Need the hostname where to find the router in the configuration");
    }
    if (sm_port == 0) {
	throw Glib::ustring("Need the port number of the router in the configuration");
    }
    if (sm_id.length() == 0) {
	throw Glib::ustring("Need our ID on the router in the configuration");
    }
    if (sm_secret.length() == 0) {
	throw Glib::ustring("Need the secret for the router in the configuration");
    }
    if (local_id.empty()) {
	throw Glib::ustring("Need our domain(s) for which connections should be accepted in the config");
    }

    /* authentication configuration stuff */
    sasl_enabled = config->find("authentication") != config->end();
    if (sasl_enabled != 0) {
	sasl_xep0078 = config->find("authentication.legacyauth") != config->end();
	try {
	    sasl_appname = config->get_string("authentication.appname");
	} catch (Glib::ustring) {
	    DBG("Set no authentication.appname");
	}
	if (sasl_appname.length() == 0) {
	    sasl_appname = PACKAGE;
	}
	try {
	} catch (Glib::ustring) {
	    DBG("Set no authentication.service");
	}
	if (sasl_service.length() == 0) {
	    sasl_service = "xmpp";
	}
	try {
	    sasl_fqdn = config->get_string("authentication.fqdn");
	} catch (Glib::ustring) {
	    DBG("Set no authentication.fqdn");
	}
	try {
	    sasl_defaultrealm = config->get_string("authentication.defaultrealm");
	} catch (Glib::ustring) {
	    DBG("Set no authentication.defaultrealm");
	}
	try {
	    sasl_min_ssf = config->get_integer("authentication.minssf");
	} catch (Glib::ustring) {
	    sasl_min_ssf = 0;
	}
	try {
	    sasl_max_ssf = config->get_integer("authentication.maxssf");
	} catch (Glib::ustring) {
	    throw std::invalid_argument("Problem with the authentication.maxssf setting");
	}
	sasl_noseclayer = config->find("authentication.noseclayer") != config->end();
	try {
	    sasl_sec_flags = config->get_integer("authentication.secflags");
	} catch (Glib::ustring) {
	    throw std::invalid_argument("Problem with the authentication.secflags setting");
	}
	if (config->find("authentication.admin") != config->end()) {
	    sasl_admin = (*config)["authentication.admin"];
	}
    }
}

c2s_st::~c2s_st() {
    DBG("Destroying c2s_st instance");
}

void c2s_st::parse_commandline(int argc, char * const*argv) {
    char optchar = 0;

    // START OLDCODE
    while ((optchar = getopt(argc, argv, "c:r:bh?")) >= 0) {
        switch(optchar) {
            case 'h':
	    case '?':
                usage();
		throw Glib::ustring("");
	    case 'r':
		rand_dev = optarg;
		break;
		// END OLDCODE
            case 'c':
		try {
		    config = new xmppd::configuration(optarg);
		    config_loaded = true;
		} catch (...) {
		    std::cerr << "Could not load configuration " << optarg << std::endl;
		}
                break;
		// START OLDCODE
    	    case 'b':
                /* !!! needs testing */
                /* !!! should this be a cmdline option, or in the config? */
                daemonize();
                break;	       
        }
    }
    // END OLDCODE
}

void c2s_st::seed_random() {
    unsigned int rand_seed = 0;
    int fd = 0;

    // we prefere using the urandom device to seed our random number generator.
    fd = open(rand_dev.c_str(), O_RDONLY|O_NOCTTY);
    if (fd != -1) {
	read(fd, &rand_seed, sizeof(rand_seed));
	close(fd);
    }

    // if this is not possible, we use the current time
    if (rand_seed == 0) {
	log->level(LOG_NOTICE) << "could not seed random number generator from " << rand_dev << " - using time";
	rand_seed = time(NULL);
    }

    // now seed the random number generator
    srand(rand_seed);
}

void c2s_st::start_logging() {
    log = new xmppd::logging(sm_id);
    log->level(LOG_NOTICE) << "starting up as " << sm_id << " (" << PACKAGE << " " << VERSION << ")";
}

/* although this is our main and it's an all-in-one right now,
 * it's done in a way that would make it quite easy to thread, 
 * customize, or integrate with another codebase
 */
int main(int argc, char* const* argv) {
    time_t last_log, last_pending, last_jid_clean, now;
    int i, fd;
    int sasl_result = 0;

    signal(SIGINT, onSignal);
    signal(SIGPIPE, SIG_IGN);
    
    // create the instance of jadc2s
    xmppd::pointer<c2s_st> c2s = NULL;
    try {
	c2s = new c2s_st(argc, argv);
    } catch (std::logic_error err) {
	std::cerr << "cought logic error on creating c2s_st instance:\n" << err.what() << std::endl;
	return 1;
    } catch (Glib::ustring message) {
	std::cerr << message << std::endl;
	usage();
	return 1;
    }

    DBG("c2s_st instance created");

    // process configuration data
    try {
	c2s->configurate(c2s);
    } catch (Glib::ustring message) {
	std::cerr << message << std::endl;
	return 1;
    }

    // start logging
    c2s->start_logging();

    /* seed the random number generator */
    c2s->seed_random();

    /* first, make sure we can connect to our sm */
    if (!connect_new(c2s)) {
	c2s->log->level(LOG_ERR) << "Unable to connect to sm!";
        exit(1);
    }

    /* only bind the unencrypted port if we have a real port number for it */
    if (c2s->local_port > 0) {
        /* then make sure we can listen */
        if (mio_listen(c2s->mio, c2s->local_port, c2s->local_ip.c_str(), client_io, &c2s) < 0) {
	    c2s->log->level(LOG_ERR) << "failed to listen on port " << c2s->local_port << "!";
            return 1;
        }

	c2s->log->level(LOG_NOTICE) << "listening for client connections on port " << c2s->local_port;
    }

#ifdef USE_SSL
    /* get the SSL port all set up */
// XXX    if(c2s->local_sslport == 0 || c2s->pemfile == NULL)
    if (c2s->pemfile.length() == 0)
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
        if (SSL_CTX_use_certificate_file(c2s->ssl_ctx, c2s->pemfile.c_str(), SSL_FILETYPE_PEM) != 1) {
	    c2s->log->level(LOG_WARNING) << "failed to load certificate from " << c2s->pemfile << ", SSL/TLS disabled";
	    c2s->log->level(LOG_WARNING).ssl_errors();
	    c2s->ssl_ctx = NULL;
	} else if (SSL_CTX_use_PrivateKey_file(c2s->ssl_ctx, c2s->pemfile.c_str(), SSL_FILETYPE_PEM) != 1) {
	    c2s->log->level(LOG_WARNING) << "failed to load private key from " << c2s->pemfile << ", SSL/TLS disabled";
	    c2s->log->level(LOG_WARNING).ssl_errors();
	    c2s->ssl_ctx = NULL;
	} else {
            if (!SSL_CTX_check_private_key(c2s->ssl_ctx)) {
		c2s->log->level(LOG_WARNING) << "private key does not match certificate public key, SSL/TLS disabled";
		c2s->log->level(LOG_WARNING).ssl_errors();
		c2s->ssl_ctx = NULL;
	    } else {
		if (c2s->ciphers.length() > 0 && !SSL_CTX_set_cipher_list(c2s->ssl_ctx, c2s->ciphers.c_str())) {
		    c2s->log->level(LOG_ERR) << "non of the configured ciphers could be enabled, SSL/TLS disabled";
		    c2s->log->level(LOG_ERR).ssl_errors();
		    c2s->ssl_ctx = NULL;
		}
		if (c2s->local_sslport != 0 ) {
		    if (mio_listen(c2s->mio, c2s->local_sslport, c2s->local_ip.c_str(), client_io, &c2s) < 0)
			c2s->log->level(LOG_ERR) << "failed to listen on port " << c2s->local_sslport << "!";
		    else
			c2s->log->level(LOG_NOTICE) << "listening for SSL/TLS client connections on port " << c2s->local_sslport;
		}
	    }
        }

	/* enable workarounds for different SSL client bugs or disable
	 * some versions of SSL/TLS */
	if (c2s->ssl_ctx != NULL) {
	    if (c2s->ssl_enable_workarounds)
		SSL_CTX_set_options(c2s->ssl_ctx, SSL_OP_ALL);
	    if (c2s->ssl_no_ssl_v2)
		SSL_CTX_set_options(c2s->ssl_ctx, SSL_OP_NO_SSLv2);
	    if (c2s->ssl_no_ssl_v3)
		SSL_CTX_set_options(c2s->ssl_ctx, SSL_OP_NO_SSLv3);
	    if (c2s->ssl_no_tls_v1)
		SSL_CTX_set_options(c2s->ssl_ctx, SSL_OP_NO_TLSv1);
	}
    }
#endif

#ifdef WITH_SASL
    if (c2s->sasl_enabled != 0) {
	int i = 0;
	for (i=0; sasl_callbacks[i].id!=SASL_CB_LIST_END; i++) {
	    DBG("callback init for " << i);
	    sasl_callbacks[i].context = &c2s;
	}
	sasl_result = sasl_server_init(sasl_callbacks, c2s->sasl_appname.c_str());
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
            if(c2s->local_statfile.length() > 0) {
		std::ofstream statfile(c2s->local_statfile.c_str());
		if (statfile)
		    statfile << c2s->num_clients;
            }
            last_log = time(NULL);
        }

        /* !!! XXX Should these be configurable cleanup times? */
        /* every so often check for timed out pending conns */
	/*
        if((time(&now) - last_pending) > 15) {
	    std::map<Glib::ustring, conn_t>::iterator p;
	    for (p = c2s->pending.begin(); p != c2s->pending.end(); ++p) {
		// XXX we should not need this, but currently we do ... why?
		if (p->second == NULL) {
		    c2s->log->level(LOG_NOTICE) << "we have to erase " << p->first << " out of c2s->pending.";
		    c2s->pending.erase(p->first);
		    continue;
		}
		if (now - p->second->start > c2s->timeout && p->second->fd != -1) {
		    conn_close(p->second, STREAM_ERR_TIMEOUT, "You have not authenticated in time");
		}
	    }
            last_pending = time(NULL);
        }
	*/

	/* cleanup the stringprep caches */
	if ((time(NULL) - last_jid_clean) > 60) {
	    c2s->used_jid_environment.nodes->clean_cache();
	    c2s->used_jid_environment.domains->clean_cache();
	    c2s->used_jid_environment.resources->clean_cache();
	}

        /* !!! XXX Move this in here for optimization? */
        connection_rate_cleanup(c2s);

        /* XXX This still feels odd having more stuff in here */
        check_karma(c2s);
    }

    /* TODO: Notify sessionmanager about shutdown */
    c2s->log->level(LOG_NOTICE) << "shutting down";

    /* close client connections */
    std::vector<conn_st*>::iterator p;
    for (p=c2s->conns.begin(); p!=c2s->conns.end(); ++p) {
	if ((*p)->fd != -1 && (*p)->fd != c2s->sm->fd)
	    conn_close(*p, STREAM_ERR_SYSTEM_SHUTDOWN, "shutting down " PACKAGE);
    }

    DBG("Closed open client connections");

    /* close session manager connection */
    c2s->shutting_down = 1;
    conn_close(c2s->sm, "", "");

    /* exiting, clean up */
    mio_free(c2s->mio);

    for (p=c2s->conns.begin(); p!=c2s->conns.end(); ++p) {
	delete *p;
    }

    nad_cache_free(c2s->nads);
    if (c2s->log != NULL)
	delete c2s->log;
    c2s->log = NULL;
#ifdef USE_SSL
    SSL_CTX_free(c2s->ssl_ctx);
#endif

    return 0;
}
