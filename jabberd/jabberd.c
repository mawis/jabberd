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

int main (int argc, char** argv)
{
    sigset_t set;               /* a set of signals to trap */
    int help, sig, i;           /* temporary variables */
    char *cfgfile = NULL, *c, *cmd, *home = NULL;   /* strings used to load the server config */
    pool cfg_pool=pool_new();
    xmlnode temp_greymatter;
    xmlnode pidfile;
    char *pidpath;

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
                debug_flag = 1;
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
        debug_flag = 1;
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

    /* karma granted, rock on */
    if(configo(1))
        exit(1);

    /* begin delivery of queued msgs */
    deliver__flag=1;
    deliver(NULL,NULL);

    /* trap signals HUP, INT and TERM */
    sigemptyset(&set);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pth_sigmask(SIG_UNBLOCK, &set, NULL);

    /* main server loop */
    while(1)
    {
        xmlnode cur;

        /* wait for a signal */
        pth_sigwait(&set, &sig);

        /* if it's not HUP, exit the loop */
        if(sig != SIGHUP) break;

        log_notice(NULL,"SIGHUP recieved.  Reloading config file");

        log_debug(ZONE, "Saving old greymatter");
        /* keep greymatter around till we are sure the reload is OK */
        temp_greymatter = greymatter__;

        log_debug(ZONE, "Loading new config file");
        /* try to load the config file */
        if(configurate(cfgfile))
        { /* failed to load.. restore the greymatter */
            log_debug(ZONE, "Failed to load new config, resetting greymatter");
            log_alert(ZONE, "Failed to reload config!  Resetting internal config -- please check your configuration!");
            greymatter__ = temp_greymatter;
            continue;
        }

        /* make sure that this config is okay */
        log_debug(ZONE, "Validating Instances");
        if(configo(0))
        { /* bad config.. reload the old */
            log_debug(ZONE, "Failed to Validate Instances");
            log_alert(ZONE, "Failed to Validate Instances!  Resetting internal config -- please check your configuration!");
            greymatter__ = temp_greymatter;
            continue; 
        }

        log_debug(ZONE, "Pausing Deliver()");
        /* pause deliver() */
        deliver__flag = 0;

        log_debug(ZONE, "Looking for new instances to startup...");
        /* look for new instances.. start them up */
        for(cur = xmlnode_get_firstchild(greymatter__); cur != NULL; cur = xmlnode_get_nextsibling(cur))
        {
            char *id;
            instance i;

            if(xmlnode_get_type(cur) != NTYPE_TAG) continue;

            id = xmlnode_get_attrib(cur, "id");
            log_debug(ZONE, "Looking at %s...", id);
            i = ghash_get(instance__ids, id);
            if(i == NULL)
            { /* new instance, start it up */
                log_debug(ZONE, "%s is a new instance! starting it up", id);
                instance_startup(cur, 1);
            }

            /* XXX FIXME: do a full sigHUP, not just start new instnaces
            else
            {
                if(xmlnode_cmp(cur, i->x) != 0)
                {
                    log_debug(ZONE, "%s is a changed instance! reloading", id);
                    instance_shutdown(i);
                    instance_startup(cur, 1);
                }
            }
            */
        }

        /* XXX FIXME: take this out, and do a full sigHUP, */
        if(1)
        {
            log_debug(ZONE, "Engaging deliver() again");
            /* engage deliver() drive ensign, full warp ahead! */
            deliver__flag = 1;
            deliver(NULL,NULL);

            log_debug(ZONE, "Freeing old greymatter");
            /* free old greymatter */
            if(temp_greymatter != NULL)
                xmlnode_free(temp_greymatter);

            log_debug(ZONE, "Reload process complete, going back to waiting for a signal");
            continue;
        }

        log_debug(ZONE, "Looking for stale instances to shut down...");
        /* look for stale instances to shutdown */
        for(cur = xmlnode_get_firstchild(temp_greymatter); cur != NULL; cur = xmlnode_get_nextsibling(cur))
        {
            char *searchstr;
            if(xmlnode_get_type(cur) != NTYPE_TAG) continue;

            searchstr = spools(xmlnode_pool(cur), xmlnode_get_name(cur), "?id=", xmlnode_get_attrib(cur, "id"), xmlnode_pool(cur));
            log_debug(ZONE, "Checking if %s is stale", searchstr);

            if(xmlnode_get_tag(greymatter__, searchstr) == NULL)
            { /* was in config, but not anymore */
                instance i;
                log_alert(NULL, "Shutting Down stale instance %s", xmlnode_get_attrib(cur, "id"));
                
                i = ghash_get(instance__ids, xmlnode_get_attrib(cur, "id"));
                instance_shutdown(i);
            }
        }

        log_debug(ZONE, "Engaging deliver() again");
        /* engage deliver() drive ensign, full warp ahead! */
        deliver__flag = 1;
        deliver(NULL,NULL);

        log_debug(ZONE, "Freeing old greymatter");
        /* free old greymatter */
        if(temp_greymatter != NULL)
            xmlnode_free(temp_greymatter);

        log_debug(ZONE, "Reload process complete, going back to waiting for a signal");

    }

    log_alert(NULL,"Recieved Kill.  Jabberd shutting down.");
    /* we left the main loop, so we must have recieved a kill signal */
    /* start the shutdown sequence */

    /* XXX pause deliver() this sucks, cuase we lose shutdown messages */
    deliver__flag = 0;
//    instance_shutdown(NULL);
    shutdown_callbacks();

    /* one last chance for threads to finish shutting down */
    pth_sleep(1);

    /* stop MIO */
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
    pool_free(cfg_pool);
    xmlnode_free(greymatter__);

    /* base modules use jabberd__runtime to know when to shutdown */
    pool_free(jabberd__runtime);

    /* we're done! */
    return 0;

}
