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
 *  services.c -- services API
 *
 */

#include "jsm.h"


/*
 *  js_service_prescreen -- authenticate a user
 *
 *  Services call this function to handle user authentication
 *  It relies on authentication modules to do the actual 
 *  authentication, and transforms the xmlnode in the packet
 *  into an appropriate response
 *
 *  parameters
 *      p -- the register or auth packet
 *
 *  returns
 *      S_AUTHED if authentication was successful 
 *      S_BOUNCE if not
 */
sreturn js_service_prescreen(jpacket p)
{
    static mmaster om = NULL;   /* master list of module callbacks for OFFLINE packets */
    udata user;                 /* the user data to authenticate against */
    char *u, *ul;               /* string buffer and index pointer for the user name */
    jid test;                   /* a jid to attempt to retreive user data with */

    /* initialize the call back list if necessary */
    if(om == NULL) om = js_mapi_master(P_OFFLINE);

    /* if there was no packet, skip authentiction */
    if(p == NULL) return S_IGNORE;

    /* get the username supplied by the client */
    u = xmlnode_get_tag_data(p->iq,"username");
    if(u != NULL)
    {
        /* enforce the username to lowercase for registration */
        for(ul = u;*ul != '\0'; ul++)
            *ul = tolower(*ul);

        /* see if the username is valid */
        test = jid_new(p->p,"test");
        jid_set(test,u,JID_USER);

        /* was the username acceptable */
        if(test->user == NULL)
        {
            /* bad username, create an error node */
            jutil_error(p->x, TERROR_NOTACCEPTABLE);
            return S_BOUNCE;
        }
    }

    /* is this an auth request? */
    if(p->type == JPACKET_IQ && NSCHECK(p->iq,NS_AUTH))
    {
        /* debug message */
        log_debug(ZONE,"auth request");

        /* attempt to fetch user data based on the username */
        user = js_user(u);
        if(user == NULL || xmlnode_get_tag_data(p->iq,"resource") == NULL)
        {
            /*
             * no user on this server or no resource sent
             * so transform the node into an error node 
             */
            jutil_error(p->x, TERROR_AUTH);

        }else{

            /* found the user data, try to authenticate */
            if(js_mapi_call(P_OFFLINE, om->l, p, user, NULL, MAPI_VARAUTH))
            {
                /*
                 * some module handled the auth packet, so rebuild
                 * the packet data from the raw node, because the module
                 * will have changed the node into an appropriate response
                 */
                jpacket_reset(p);

                /* if the packet is now an iq result, the auth was successful */
                if(jpacket_subtype(p) == JPACKET__RESULT)
                    return S_AUTHED;

            }else{

                /*
                 * no module handled the call, so the auth failed:
                 * transform the node into an error node
                 */
                jutil_error(p->x, TERROR_INTERNAL);
            }

        }

        /* is this a registration request? */
    }else if(p->type == JPACKET_IQ && NSCHECK(p->iq,NS_REGISTER)){

        /* debug message */
        log_debug(ZONE,"registration request");

        /* try to register via a module */
        if(!js_mapi_call(P_OFFLINE, om->l, p, NULL, NULL, MAPI_VARREGISTER))

            /* registration failed, transform node into an error node */
            jutil_error(p->x, TERROR_NOTIMPL);

    }else{

        /*
         * the packet wasn't an auth *or* registration request so 
         * transform the node into an error message stating that
         * authentication is required
         */
        jutil_error(p->x, TERROR_AUTH);
    }

    /* if we go this far, auth failed */
    return S_BOUNCE;

}

/*
 *  js_service_listen -- start the listen thread(s) for the service based on the configuration
 *
 *  parameters
 *      svc -- the name of the service
 *      evt -- the handler for new connections on the tlisten port
 */
void js_service_listen(char *svc, tlisten_onConnect evt)
{

    xmlnode x;      /* data from the config */
    char *ip;       /* IP address or hostname to listen on */
    int port;       /* port to listen on */
    int flag = 0;   /* set to true when the listen is successful */

    /* scan the config file listen entries */
    for(x = xmlnode_get_firstchild(js_config("listen")); x != NULL; x = xmlnode_get_nextsibling(x))
    {
        /* if the service name doesn't match the config, skip to the next one */
        if(j_strcmp(xmlnode_get_name(x),svc) != 0) continue;

        /* attempt to get the port from the node data */
        if(xmlnode_get_data(x) == NULL || sscanf(xmlnode_get_data(x), "%d", &port) == 0) continue;

        /* get the hostname from the ip attribute if available */
        ip = xmlnode_get_attrib(x,"ip");

        /* create thread to listen on the host and port */
        if(tlisten_new(port, ip, evt, NULL) == NULL)
        {
            log_error("jsm","failed to listen on %s:%d",ip,port);
        }else{
            log_debug(ZONE,"listening on %s:%d",ip,port);
            flag = 1;
        }
    }

    /* log and error if the listen failed */
    if(flag == 0)
        log_error("jsm","Failed to listen for service %s",svc);
}
