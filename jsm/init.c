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
 *  Copyright (C) 1998-1999 The Jabber Team http://jabber.org/
 *
 *  init.c -- start system threads and listen for connections
 *
 */

#include "jserver.h"
#ifdef HAVE_OPENSSL
#include "svc/client/svc_client_ssl.h"
#endif /* HAVE_OPENSSL */


/*
 *  jabber_transport -- start all system threads
 *
 */
void jabber_transport()
{

    pth_attr_t attr;        /* thread attributes */
    char *log;              /* error log */

    log = xmlnode_get_data(js_config("log/error"));
    if(j_strcmp(log,"syslog") == 0)
    {
        log_init(LOGSYSLOG,"jabber");
    }else if(log != NULL){
        log_init(LOGFILE,log);
    }else{
        log_init(LOGSTDERR,NULL);
        log_warn("jserver","Error log not configured, printing to STDERR");
    }

    log_warn("jserver","Initializing Services");

    /* set up attributes for system threads */
    attr = pth_attr_new();
    pth_attr_set(attr, PTH_ATTR_JOINABLE, FALSE);
    pth_attr_set(attr, PTH_ATTR_STACK_SIZE, etherx_stack_default);

    /* start system threads */
    pth_spawn(attr, js_unknown_main, NULL); /* the thread handling all unknown packets */
    pth_spawn(attr, js_offline_main, NULL); /* the thread handling all offline packets */
    pth_spawn(attr, js_server_main, NULL);  /* all traffic to server resources */
    pth_spawn(attr, js_users_main, NULL);   /* free cached user data */
    /*    pth_spawn(attr, js_debug_main, NULL);*/

    /* free attribute structure */
    pth_attr_destroy(attr);

    /* let pth start the threads */
    pth_yield(NULL);

    /* initialize list of names */
    js_config_name(C_INIT,NULL);

    /* init the default services */
    js_service_listen("jabber", js_conn_connect);
#ifdef HAVE_OPENSSL
    js_service_listen("ssl", svc_ssl_connect);
#endif
    /* start all the static components */
    js_static();

}


