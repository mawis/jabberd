/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "License").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the License.  You
 * may obtain a copy of the License at http://www.jabber.com/license/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2000 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * --------------------------------------------------------------------------*/
 
/*
 * Doesn't he wish!
 *
 * <ChatBot> jer: Do you sometimes wish you were written in perl?
 *
 */

#include "jabberd.h"
#include "single.h"
HASHTABLE cmd__line, debug__zones;
extern HASHTABLE instance__ids;
extern int deliver__flag;
extern xmlnode greymatter__;
pool jabberd__runtime = NULL;
static char *cfgfile = NULL;
int jabberd__signalflag = 0;

/*** internal functions ***/
int configurate(char *file);
void static_init(void);
void dynamic_init(void);
void deliver_init(void);
void heartbeat_birth(void);
void heartbeat_death(void);
int configo(int exec);
void shutdown_callbacks(void);
int config_reload(char *file);
int  instance_startup(xmlnode x, int exec);
void instance_shutdown(instance i);
void _jabberd_signal(int sig);


int main (int argc, char** argv)
{
    int help, i;           /* temporary variables */
    char *c, *cmd, *home = NULL;   /* strings used to load the server config */
    pool cfg_pool=pool_new();
    float avload;

    jabberd__runtime = pool_new();

    /* start by assuming the parameters were entered correctly */
    help = 0;
    cmd__line = ghash_create_pool(jabberd__runtime, 11,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);

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
            if(*c == 'D')
            {
                set_debug_flag(1);
                continue;
            }
            if(*c == 'V' || *c == 'v')
            {
                printf("Jabberd Version %s\n", VERSION);
                exit(0);
            }

            cmd = pmalloco(cfg_pool,2);
            cmd[0]=*c;
            if(i+1<argc)
            {
               ghash_put(cmd__line,cmd,argv[++i]);
            }else{
                help=1;
                break;
            }
        }
    }

    /* the special -Z flag provides a list of zones to filter debug output for, flagged w/ a simple hash */
    if((cmd = ghash_get(cmd__line,"Z")) != NULL)
    {
        set_debug_flag(1);
        debug__zones = ghash_create_pool(jabberd__runtime, 11,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
        while(cmd != NULL)
        {
            c = strchr(cmd,',');
            if(c != NULL)
            {
                *c = '\0';
                c++;
            }
            ghash_put(debug__zones,cmd,cmd);
            cmd = c;
        }
    }else{
        debug__zones = NULL;
    }

#ifdef SINGLE
    SINGLE_STARTUP
#else
    /* were there any bad parameters? */
    if(help)
    {
        fprintf(stderr,"Usage:\njabberd &\n Optional Parameters:\n -c\t\t configuration file\n -D\t\tenable debug output\n -H\t\tlocation of home folder\n -v\t\tserver version\n -V\t\tserver version\n");
        exit(0);
    }

    if((home = ghash_get(cmd__line,"H")) == NULL)
        home = pstrdup(jabberd__runtime,HOME);
#endif

    /* change the current working directory so everything is "local" */
    if(home != NULL && chdir(home))
        fprintf(stderr,"Unable to access home folder %s: %s\n",home,strerror(errno));

    /* load the config passing the file if it was manually set */
    cfgfile=ghash_get(cmd__line,"c");
    if(configurate(cfgfile))
        exit(1);

    /* EPIPE is easier to handle than a signal */
    signal(SIGPIPE, SIG_IGN);

    /* handle signals */
    signal(SIGHUP,_jabberd_signal);
    signal(SIGINT,_jabberd_signal);
    signal(SIGTERM,_jabberd_signal);

    /* init pth */
    pth_init();

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
        log_debug(ZONE,"main load check of %.2f with %ld total threads", avload, pth_ctrl(PTH_CTRL_GETTHREADS));
        pth_sleep(60);
    };

    /* we never get here */
    return 0;
}

void _jabberd_signal(int sig)
{
    log_debug(ZONE,"received signal %d",sig);
    jabberd__signalflag = sig;
}

void _jabberd_restart(void)
{
    xmlnode temp_greymatter;

    log_notice(NULL, "reloading configuration");

    /* keep greymatter around till we are sure the reload is OK */
    temp_greymatter = greymatter__;

    log_debug(ZONE, "Loading new config file");

    /* try to load the config file */
    if(configurate(cfgfile))
    { /* failed to load.. restore the greymatter */
        log_debug(ZONE, "Failed to load new config, resetting greymatter");
        log_alert(ZONE, "Failed to reload config!  Resetting internal config -- please check your configuration!");
        greymatter__ = temp_greymatter;
        return;
    }

    /* free old greymatter */
    if(temp_greymatter != NULL)
        xmlnode_free(temp_greymatter);

    /* XXX do more smarts on new config */

    log_debug(ZONE, "reload process complete");

}

void _jabberd_shutdown(void)
{
    xmlnode pidfile;
    char *pidpath;

    log_notice(NULL,"shutting down server");

    /* pause deliver() this sucks, cuase we lose shutdown messages */
    deliver__flag = 0;
    shutdown_callbacks();

    /* one last chance for threads to finish shutting down */
    pth_sleep(1);

    /* stop MIO and heartbeats */
    mio_stop();
    heartbeat_death();

    /* kill any leftover threads */
    pth_kill();

    /* Get rid of our pid file */
    pidfile = xmlnode_get_tag(greymatter__, "pidfile");
    if(pidfile != NULL)
    {
        pidpath = xmlnode_get_data(pidfile);
        if(pidpath != NULL)
            unlink(pidpath);
    }
    xmlnode_free(greymatter__);

    /* base modules use jabberd__runtime to know when to shutdown */
    pool_free(jabberd__runtime);

    exit(0);
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
