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
 * @file jabberd.cc
 * @brief Where all begins ... this file contains the main function, shutdown routines and signal handlers
 */

/*
 * Doesn't he wish!
 *
 * <ChatBot> jer: Do you sometimes wish you were written in perl?
 *
 */

#include <pwd.h>
#include <grp.h>

#include "jabberd.h"

#ifdef HAVE_SYSLOG
#include <syslog.h>
#endif

#include <popt.h>

xht debug__zones = NULL;		/**< the debugging zones, that are enabled (key = zone string, value = zone string) */
extern int deliver__flag;
extern xmlnode greymatter__;

extern xht instance__ids;

/*** internal functions ***/
void base_init(pool p);
int configo(int exec);
int configurate(char *file, xht cmd_line, int is_restart);
void deliver_init(pool p);
void deliver_shutdown(void);
void heartbeat_birth(void);
void heartbeat_death(void);
void shutdown_callbacks(void);
static void _jabberd_signal(int sig);
static void _jabberd_atexit(void);
static result jabberd_signal_handler(void *arg);

/**
 * structure that holds 'global' data
 */
typedef struct {
    xht		cmd_line;	/**< hash where unused command-line options are stored to */
    pool	runtime_pool;	/**< memory pool with a livetime of the jabber server */
    int		signalflag;	/**< set to the signal value, if jabberd receives a signal */
    char*	cfgfile;	/**< configuration file the user specified at the command line (NULL for the default file) */
} jabberd_struct;

jabberd_struct jabberd = { NULL, NULL, 0, NULL };		/**< global data for the jabberd */

void xmlnode_stat();
void deliver_pool_debug();

/**
 * the entry point to jabberd
 *
 * @param argc the number of arguments on the command line used to start jabberd
 * @param argv array of the arguments
 * @return 0 on successfull shutdown, 1 else
 */
int main (int argc, const char** argv) {
    char *c = NULL;
    char *cmd = NULL;
    char *home = NULL;
    char *zones = NULL;		/* debugging zones */
    char *host = NULL;		/* domain/hostname to run as */
    char *spool = NULL;		/* spool directory for xdb_file */
    char *import_spool = NULL;	/* spool base dir for import */
    char *do_include = NULL;	/* include files in configuration */
    float avload;
    int do_debug = 0;           /* Debug output option, default no */
    int do_background = 0;      /* Daemonize option, default no */
    int do_version = 0;		/* print version information */
    char *run_as_user = NULL;	/* user to run jabberd as */
    poptContext pCtx = NULL;
    int pReturn = 0;		/* return code of popt */

    /*
     * command line options for jabberd14
     */
    struct poptOption options[] = {
	{ "config", 'c', POPT_ARG_STRING, &(jabberd.cfgfile), 0, "configuration file to use", "path and filename"},
	{ "include", 'i', POPT_ARG_STRING, &do_include, 0, "include configuration files", "comma separated list"},
	{ "debugmask", 'd', POPT_ARG_INT, &do_debug, 0, "enable debugging (by type)", "debugging mask"},
	{ "debug", 'D', POPT_ARG_NONE, NULL, 1, "enable debugging (all types)", NULL},
	{ "zones", 'Z', POPT_ARG_STRING, &zones, 0, "debugging zones (file names without extension)", "comma separated list"},
	{ "user", 'U', POPT_ARG_STRING, &run_as_user, 0, "run " PACKAGE " as another user", "user to run as"},
	{ "home", 'H', POPT_ARG_STRING, &home, 0, "what to use as home directory", "directory path"},
	{ "define", 'x', POPT_ARG_STRING, NULL, 2, "define a replacement string for configuration", "key:value"},
	{ "background", 'B', POPT_ARG_NONE, &do_background, 0, "background the server process", NULL},
	{ "host", 'h', POPT_ARG_STRING, &host, 0, "hostname that should be served by " PACKAGE, "domain (FQDN)"},
	{ "spooldir", 's', POPT_ARG_STRING, &spool, 0, "directory where to place the file spool of xdb_file", "directory path"},
	{ "import", 'I', POPT_ARG_STRING, &import_spool, 0, "import data to the server from a filespool", "basedir of file-spool"},
	{ "version", 'V', POPT_ARG_NONE, &do_version, 0, "print server version", NULL},
	{ NULL, 'v', POPT_ARG_NONE|POPT_ARGFLAG_DOC_HIDDEN, &do_version, 0, "print server version", NULL},
	POPT_AUTOHELP
	POPT_TABLEEND
    };

    if (!mio_tls_early_init()) {
	return 2;
    }

    /* create hash for command line options */
    jabberd.cmd_line = xhash_new(11);
    
    /* parse command line options */
    pCtx = poptGetContext(NULL, argc, argv, options, 0);
    while ((pReturn = poptGetNextOpt(pCtx)) >= 0) {
	switch (pReturn) {
	    case 1:
		do_debug = -1;
		break;
	    case 2:
		cmd = pstrdup(jabberd.cmd_line->p, poptGetOptArg(pCtx));
		c = strchr(cmd, ':');
		if (c == NULL) {
		    fprintf(stderr, "Invalid definition for config file replacement: %s\nNeeds to be of key:value\n", cmd);
		    return 1;
		}
		c[0] = 0;
		c++;
		xhash_put(jabberd.cmd_line, cmd, c);
		cmd = c = NULL;
		break;
	}
    }

    /* error? */
    if (pReturn < -1) {
	fprintf(stderr, "%s: %s\n", poptBadOption(pCtx, POPT_BADOPTION_NOALIAS), poptStrerror(pReturn));
	return 1;
    }

    /* anything left? */
    if (poptPeekArg(pCtx) != NULL) {
	fprintf(stderr, "invalid argument: %s\n", poptGetArg(pCtx));
	return 1;
    }

    /* printing version information desired? */
    if (do_version != 0) {
	printf("%s version %s\n", PACKAGE, VERSION);
	printf("\nThe following optional features have been enabled:\n");
#ifdef WITH_IPV6
	printf("- support for IPv6.\n");
#endif
	printf("- support for TLS");
	printf(" using GNU TLS");
	printf("\n");
#ifdef HAVE_MYSQL
	printf("- support for MySQL\n");
#endif
#ifdef HAVE_POSTGRESQL
	printf("- support for PostgreSQL\n");
#endif
#ifdef HAVE_SYSLOG
	printf("- logging to syslog\n");
#endif
	printf("\nDefault config file is: %s\n", CONFIG_DIR "/jabber.xml");
	printf("Locales are in: %s\n", LOCALEDIR);
	printf("\nFor more information please visit http://jabberd.org/\n");
	printf("If you need support, check out http://jabberd.org/gettingSupport\n");
	printf("\nNOTICE: With the next release of this software, this package\n");
	printf("        will get renamed to 'xmppd'. (http://xmppd.org/)\n");
	return 0;
    }

    /* generate a memory pool that is available for the whole livetime of jabberd */
    jabberd.runtime_pool = pool_new();

    /* register this handler to remove our pidfile at exit */
    atexit(_jabberd_atexit);

    /* putting h and s to the cmd_line hash */
    if (host != NULL) {
	xhash_put(jabberd.cmd_line, "h", host);
    }
    if (spool != NULL) {
	xhash_put(jabberd.cmd_line, "s", spool);
    }
    if (do_include != NULL) {
	xhash_put(jabberd.cmd_line, "i", do_include);
    }
    if (import_spool != NULL) {
	xhash_put(jabberd.cmd_line, "I", import_spool);
    }

    /* the special -Z flag provides a list of zones to filter debug output for, flagged w/ a simple hash */
    if (zones != NULL) {
	debug__zones = xhash_new(11);
	cmd = pstrdup(debug__zones->p, zones);
        while(cmd != NULL) {
            c = strchr(cmd, ',');
            if (c != NULL) {
                *c = '\0';
                c++;
            }
            xhash_put(debug__zones, cmd, cmd);
            cmd = c;
        }
    } else {
        debug__zones = NULL;
    }

    if (do_debug && do_background) {
	printf(PACKAGE " will not background with debugging enabled.\n");
	do_background=0;
    }

#ifdef HAVE_SYSLOG
    openlog(PACKAGE, LOG_PID, LOG_DAEMON);
#endif

    /* set to debug mode if we have it */
    set_cmdline_debug_flag(do_debug);

    /* Switch to the specified user */
    if (run_as_user != NULL) {
        struct passwd* user = NULL;

        user = getpwnam(run_as_user);
        if (user == NULL) {
            fprintf(stderr, "Unable to lookup user %s.\n", cmd);
            exit(1);
        }
        
        if (setgid(user->pw_gid) < 0) {
            fprintf(stderr, "Unable to set group permissions.\n");
            exit(1);
        }
        if (setuid(user->pw_uid) < 0) {
            fprintf(stderr, "Unable to set user permissions.\n");
            exit(1);
        }
    }

    /* change the current working directory so everything is "local" */
    if(home != NULL && chdir(home))
        fprintf(stderr, "Unable to access home folder %s: %s\n", home, strerror(errno));

    /* background ourselves if we have been flagged to do so */
    if (do_background != 0) {
        if (fork() != 0) {
            exit(0);
        }
    }

    /* load the config passing the file if it was manually set */
    if(configurate(jabberd.cfgfile, jabberd.cmd_line, 0))
        exit(1);

    /* EPIPE is easier to handle than a signal */
    signal(SIGPIPE, SIG_IGN);

    /* handle signals */
    signal(SIGHUP,_jabberd_signal);
    signal(SIGINT,_jabberd_signal);
    signal(SIGTERM,_jabberd_signal);

    /* init pth */
    pth_init();

#ifdef LIBIDN
    /* init the stringprep caches for jid manipulation */
    jid_init_cache();
#endif

    /* fire em up baby! */
    heartbeat_birth();

    /* register a function that regularily checks the signal flag */
    register_beat(1, jabberd_signal_handler, &jabberd);

    /* init MIO */
    mio_init();

    base_init(jabberd.runtime_pool);
    deliver_init(jabberd.runtime_pool);

    /* everything should be registered for the config pass, validate */
    deliver__flag = 0; /* pause deliver() while starting up */
    if (configo(0))
        exit(1);

    log_notice(NULL, "initializing server");

    /* karma granted, rock on */
    if(configo(1))
        exit(1);

    /* begin delivery of queued msgs */
    deliver__flag=1;
    deliver(NULL,NULL);

    /* was there a request to import an existing filespool? */
    if (import_spool != NULL) {
    }

    while (1) {
        pth_ctrl(PTH_CTRL_GETAVLOAD, &avload);
        log_debug2(ZONE, LOGT_STATUS, "main load check of %.2f with %ld total threads", avload, pth_ctrl(PTH_CTRL_GETTHREADS));
#ifdef POOL_DEBUG
	pool_stat(0);
	xmlnode_stat();
	deliver_pool_debug();
#endif
#ifdef LIBIDN
	jid_clean_cache();
#endif
        pth_sleep(60);
    };

    /* we never get here */
    return 0;
}

/**
 * jabberd signal handler
 *
 * puts the received signal in the ::jabberd__signalflag variable and returns
 */
static void _jabberd_signal(int sig) {
    log_debug2(ZONE, LOGT_EVENT, "received signal %d", sig);
    jabberd.signalflag = sig;
}

/**
 * reload the configuration file
 *
 * this gets called if jabberd receives a SIGHUP signal
 *
 * The configuration file is reloaded, but not much is done with the reloaded configuration file yet :(
 */
static void _jabberd_restart(jabberd_struct *j) {
    xmlnode temp_greymatter;

    log_notice(NULL, "reloading configuration");

    /* keep greymatter around till we are sure the reload is OK */
    temp_greymatter = greymatter__;

    log_debug2(ZONE, LOGT_CONFIG, "Loading new config file");

    /* try to load the config file */
    if(configurate(j->cfgfile, j->cmd_line, 1))
    { /* failed to load.. restore the greymatter */
        log_debug2(ZONE, LOGT_CONFIG, "Failed to load new config, resetting greymatter");
        log_alert(ZONE, "Failed to reload config!  Resetting internal config -- please check your configuration!");
        greymatter__ = temp_greymatter;
        return;
    }

    /* free old greymatter (NOTE: shea, right! many internal tables/callbacs/etc have old config pointers :)
    if(temp_greymatter != NULL)
        xmlnode_free(temp_greymatter); */

    /* XXX do more smarts on new config */

    log_debug2(ZONE, LOGT_CONFIG, "reload process complete");

}

/**
 * shutdown the jabberd process
 *
 * this gets called if jabberd receives any non-SIGHUP signal
 */
static void _jabberd_shutdown(void) {
    log_notice(NULL,"shutting down server");

    /* pause deliver() this sucks, cuase we lose shutdown messages */
    deliver__flag = 0;
    shutdown_callbacks();

    /* one last chance for threads to finish shutting down */
    pth_sleep(1);

    /* stop MIO and heartbeats */
    /* XXX disabled for jabberd 1.4.4 release, we get crashes with it
     * on shutdown. Care for it later
     */
    /* mio_stop(); */
    heartbeat_death();

    /* kill any leftover threads */
    pth_kill();

    /* exit jabberd, _jabberd_atexit() will be called */
    exit(0);
}

/**
 * do jobs, that have to be done even on fatal server shutdowns (if the exit() function is called)
 *
 * remove the pid file of this process, done in an atexit function
 * because there are multiple occurences of exit() where
 * _jabberd_shutdown is not called
 */
static void _jabberd_atexit(void) {
    xmlnode pidfile = NULL;
    char *pidpath = NULL;
    xht namespaces = NULL;

    /* Get rid of our pid file */
    namespaces = xhash_new(3);
    pool temp_pool = pool_new();
    xhash_put(namespaces, "", const_cast<void*>(static_cast<const void*>(NS_JABBERD_CONFIGFILE)));
    pidfile = xmlnode_get_list_item(xmlnode_get_tags(greymatter__, "pidfile", namespaces, temp_pool), 0);
    xhash_free(namespaces);
    if (pidfile != NULL) {
        pidpath = xmlnode_get_data(pidfile);
        if(pidpath != NULL)
            unlink(pidpath);
    }
    xmlnode_free(greymatter__);
    pidfile = NULL;
    pidpath = NULL;
    pool_free(temp_pool);
    temp_pool = NULL;

    /* free delivery hashes */
    deliver_shutdown();

#ifdef LIBIDN
    /* free stringprep caches */
    jid_stop_caching();
#endif

    /* free instances hash table */
    if (instance__ids != NULL)
	xhash_free(instance__ids);

    /* free command line options */
    if (jabberd.cmd_line != NULL)
	xhash_free(jabberd.cmd_line);

    /* free remaining global memory pools */
    if (jabberd.runtime_pool != NULL)
	pool_free(jabberd.runtime_pool);
    
#ifdef POOL_DEBUG
    /* print final pool statistics ... what we missed to free */
    pool_stat(1);
#endif
}

/**
 * check if a signal has been received, and process
 *
 * @param arg pointer to an int, that contains the last received signal
 */
static result jabberd_signal_handler(void *arg) {
    jabberd_struct *j = (jabberd_struct *)arg;

    /* no flag value location is given ... giving checks up */
    if (j == NULL)
	return r_UNREG;

    /* action based on the content of the signalflag */
    switch (j->signalflag) {
	case 0:		/* no signal received */
	    break;
	case SIGHUP:
	    _jabberd_restart(j);
	    j->signalflag = 0;
	    break;
	default:
	    _jabberd_shutdown();
    }

    return r_DONE;
}
