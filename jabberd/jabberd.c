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
 * 
 * --------------------------------------------------------------------------*/
 
/*
 * Doesn't he wish!
 *
 * <ChatBot> jer: Do you sometimes wish you were written in perl?
 *
 */

#include <pwd.h>
#include <grp.h>

#include "jabberd.h"
#include "single.h"

#ifdef HAVE_SYSLOG
#include <syslog.h>
#endif

xht cmd__line, debug__zones;
extern int deliver__flag;
extern xmlnode greymatter__;
pool jabberd__runtime = NULL;
static char *cfgfile = NULL;
int jabberd__signalflag = 0;

extern xht instance__ids;

/*** internal functions ***/
int configurate(char *file, xht cmd_line);
void static_init(void);
void dynamic_init(void);
void deliver_init(void);
void deliver_shutdown(void);
void heartbeat_birth(void);
void heartbeat_death(void);
int configo(int exec);
void shutdown_callbacks(void);
void instance_shutdown(instance i);
void _jabberd_signal(int sig);
void _jabberd_atexit(void);


int main (int argc, char** argv)
{
    int help, i;           /* temporary variables */
    char *c, *cmd, *home = NULL;   /* strings used to load the server config */
    pool cfg_pool=pool_new();
    float avload;
    int do_debug = 0;           /* Debug output option, default no */
    int do_background = 0;      /* Daemonize option, default no */

    register_shutdown((shutdown_func)pool_free, cfg_pool);

    jabberd__runtime = pool_new();

    /* register this handler to remove our pidfile at exit */
    atexit(_jabberd_atexit);

    /* start by assuming the parameters were entered correctly */
    help = 0;
    cmd__line = xhash_new(11);

    /* process the parameterss one at a time */
    for(i = 1; i < argc; i++)
    {
        if(argv[i][0]!='-')
        { /* make sure it's a valid command */
            help=1;
            break;
        }
        for(c=argv[i]+1;c[0]!='\0';c++)
        {
            /* loop through the characters, like -Dc */
            if(*c == 'V' || *c == 'v')
            {
                printf("Jabberd Version %s\n", VERSION);
                exit(0);
            }
            else if(*c == 'B')
            {
		do_background = 1;
                continue;
            }
	    else if(*c == 'D')
	    {
		do_debug = -1;
		continue;
	    }

            cmd = pmalloco(cfg_pool,2);
            cmd[0]=*c;
            if(i+1<argc)
            {
               xhash_put(cmd__line,cmd,argv[++i]);
            }else{
                help=1;
                break;
            }
        }
    }

    /* the special -Z flag provides a list of zones to filter debug output for, flagged w/ a simple hash */
    if((cmd = xhash_get(cmd__line,"Z")) != NULL)
    {
        set_cmdline_debug_flag(-1);
	debug__zones = xhash_new(11);
        while(cmd != NULL)
        {
            c = strchr(cmd,',');
            if(c != NULL)
            {
                *c = '\0';
                c++;
            }
            xhash_put(debug__zones,cmd,cmd);
            cmd = c;
        }
    }else{
        debug__zones = NULL;
    }

    /* the -D flag provides a bitmask of debug types the user want to be logged */
    if((cmd = xhash_get(cmd__line,"d")) != NULL) {
	do_debug = atoi(cmd);

	if (!do_debug) {
	    printf("Invalid parameter for the -D flag, specify a bitmask.\n-D ignored\n");
	}
	
    }

    if (do_debug && do_background) {
	printf(PACKAGE " will not background with debugging enabled.\n");
	do_background=0;
    }

    /* were there any bad parameters? */
    if(help)
    {
        fprintf(stderr,"Usage:\n%s [params]\n Optional Parameters:\n -c <file>\tconfiguration file\n -d <typemask>\tenable debug output (disables background)\n -U user\t Run as user\n -D\t\tenable debug (all types)\n -H\t\tlocation of home folder\n -B\t\tbackground the server process\n -Z <zones>\tdebug zones (comma separated list)\n -v\t\tserver version\n -V\t\tserver version\n", argv[0]);
        exit(0);
    }

#ifdef HAVE_SYSLOG
    openlog(PACKAGE, LOG_PID, LOG_DAEMON);
#endif

    /* set to debug mode if we have it */
    set_cmdline_debug_flag(do_debug);

#ifdef SINGLE
    SINGLE_STARTUP
#else
    if((home = xhash_get(cmd__line,"H")) == NULL)
        home = pstrdup(jabberd__runtime,HOME);
#endif
    /* Switch to the specified user */
    if ((cmd = xhash_get(cmd__line, "U")) != NULL)
    {
        struct passwd* user = NULL;

        user = getpwnam(cmd);
        if (user == NULL)
        {
            fprintf(stderr, "Unable to lookup user %s.\n", cmd);
            exit(1);
        }
        
        if (setgid(user->pw_gid) < 0)
        {
            fprintf(stderr, "Unable to set group permissions.\n");
            exit(1);
        }
        if (setuid(user->pw_uid) < 0)
        {
            fprintf(stderr, "Unable to set user permissions.\n");
            exit(1);
        }
    }

    /* change the current working directory so everything is "local" */
    if(home != NULL && chdir(home))
        fprintf(stderr,"Unable to access home folder %s: %s\n",home,strerror(errno));

    /* background ourselves if we have been flagged to do so */
    if(do_background != 0)
    {
        if (fork() != 0)
        {
            exit(0);
        }
    }

    /* load the config passing the file if it was manually set */
    cfgfile=xhash_get(cmd__line,"c");
    if(configurate(cfgfile, cmd__line))
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

    /* init MIO */
    mio_init();

    static_init();
    dynamic_init();
    deliver_init();

    /* everything should be registered for the config pass, validate */
    deliver__flag = 0; /* pause deliver() while starting up */
    if(configo(0))
        exit(1);

    log_notice(NULL,"initializing server");

    /* karma granted, rock on */
    if(configo(1))
        exit(1);

    /* begin delivery of queued msgs */
    deliver__flag=1;
    deliver(NULL,NULL);

    while(1)
    {
        pth_ctrl(PTH_CTRL_GETAVLOAD, &avload);
        log_debug2(ZONE, LOGT_STATUS, "main load check of %.2f with %ld total threads", avload, pth_ctrl(PTH_CTRL_GETTHREADS));
#ifdef POOL_DEBUG
	pool_stat(0);
#endif
#ifdef LIBIDN
	jid_clean_cache();
#endif
        pth_sleep(60);
    };

    /* we never get here */
    return 0;
}

void _jabberd_signal(int sig)
{
    log_debug2(ZONE, LOGT_EVENT, "received signal %d", sig);
    jabberd__signalflag = sig;
}

void _jabberd_restart(void)
{
    xmlnode temp_greymatter;

    log_notice(NULL, "reloading configuration");

    /* keep greymatter around till we are sure the reload is OK */
    temp_greymatter = greymatter__;

    log_debug2(ZONE, LOGT_CONFIG, "Loading new config file");

    /* try to load the config file */
    if(configurate(cfgfile, cmd__line))
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

void _jabberd_shutdown(void)
{
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

/* remove the pid file of this process, done in an atexit function
 * because there are multiple occurences of exit() where
 * _jabberd_shutdown is not called */
void _jabberd_atexit(void)
{
    xmlnode pidfile;
    char *pidpath;

    /* Get rid of our pid file */
    pidfile = xmlnode_get_tag(greymatter__, "pidfile");
    if(pidfile != NULL)
    {
        pidpath = xmlnode_get_data(pidfile);
        if(pidpath != NULL)
            unlink(pidpath);
    }
    xmlnode_free(greymatter__);

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
    if (cmd__line != NULL)
	xhash_free(cmd__line);

    /* free remaining global memory pools */
    if (jabberd__runtime != NULL)
	pool_free(jabberd__runtime);
    
#ifdef POOL_DEBUG
    /* print final pool statistics ... what we missed to free */
    pool_stat(1);
#endif
}

/* process the signal */
void jabberd_signal(void)
{
    if(jabberd__signalflag == SIGHUP)
    {
        _jabberd_restart();
        jabberd__signalflag = 0;
        return;
    }
    _jabberd_shutdown();
}
