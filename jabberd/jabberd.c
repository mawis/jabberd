/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  Jabber
 *  Copyright (C) 1998-2000 The Jabber Team http://jabber.org/
 *
 *  jabberd.c -- brain stem
 *
 */

#include "jabberd.h"

int main (int argc, char** argv)
{
    sigset_t set;               /* a set of signals to trap */
    int help, sig, i;           /* temporary variables */
    char *cfgfile = NULL, *c;   /* strings used to load the server config */

    /* start by assuming the parameters were entered correctly */
    help = 0;

    /* process the parameterss one at a time */
    for(i = 1; i < argc; i++)
    {
        /* a pointer to the parameter */
        c = argv[i] + 1;

        /* check possible values */
        switch(*c)
        {
        case 'c': /* get name of config file */
            cfgfile = strdup(argv[++i]);
            break;

        default: /* unrecognized parameter */
            help = 1;
        }
    }

    /* were there any bad parameters? */
    if(help)
    {
        /* bad param, provide help message */
        printf("Usage:\njabberd [-c config.xml]\n");
        exit(0);
    }

    /* load the config passing the file if it was manually set */
    if(configurate(cfgfile))
        exit(1);

    /* EPIPE is easier to handle than a signal */
    signal(SIGPIPE, SIG_IGN);

    /* init pth */
    pth_init();

    /* fire em up baby! */
    loader();

    /* everything should be registered for the config pass, validate */
    if(configo(0))
        exit(1);

    /* karma granted, rock on */
    configo(1);

    /* trap signals HUP, INT and TERM */
    sigemptyset(&set);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pth_sigmask(SIG_UNBLOCK, &set, NULL);

    /* main server loop */
    while(1)
    {
        /* wait for a signal */
        pth_sigwait(&set, &sig);

        /* if it's not HUP, exit the loop */
        if(sig != SIGHUP) break;

        /* XXX it was HUP, time to reload the config file */
    }

    /* XXX we left the main loop, so we must have recieved a kill signal */

    /* XXX start the shutdown sequence */

    /* one last chance for threads to finish shutting down */
    pth_sleep(1);

    /* kill any leftover threads */
    pth_kill();

    /* we're done! */
    return 0;

}
