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


void js_authreg(void *arg)
{
    jpacket p = (jpacket)arg;
    udata user;
    char *ul;
    jsmi si = (jsmi)(p->aux1);
    xmlnode x;

    /* enforce the username to lowercase */
    if(p->to->user != NULL)
        for(ul = p->to->user;*ul != '\0'; ul++)
            *ul = tolower(*ul);

    if(p->to->user != NULL && (jpacket_subtype(p) == JPACKET__GET || p->to->resource != NULL) && NSCHECK(p->iq,NS_AUTH))
    {   /* is this a valid auth request? */

        log_debug(ZONE,"auth request");

        /* attempt to fetch user data based on the username */
        user = js_user(si, p->to, NULL);
        if(user == NULL)
        {
            jutil_error(p->x, TERROR_AUTH);
        }else if(!js_mapi_call(si, e_AUTH, p, user, NULL)){
            if(jpacket_subtype(p) == JPACKET__GET)
            { /* if it's a type="get" for auth, everybody mods it and we result and return it */
                xmlnode_insert_tag(p->iq,"resource"); /* of course, resource is required :) */
                xmlnode_put_attrib(p->x,"type","result");
                jutil_tofrom(p->x);
            }else{ /* type="set" that didn't get handled is a proble */
                jutil_error(p->x, TERROR_INTERNAL);
            }
        }

    }else if(NSCHECK(p->iq,NS_REGISTER)){ /* is this a registration request? */
        if(jpacket_subtype(p) == JPACKET__GET)
        {
            log_debug(ZONE,"registration get request");
            /* let modules try to handle it */
            if(!js_mapi_call(si, e_REGISTER, p, NULL, NULL))
            {
                jutil_error(p->x, TERROR_NOTIMPL);
            }else{ /* username/password requirements are built-in */
                jpacket_reset(p);
                xmlnode_insert_tag(p->iq,"username");
                xmlnode_insert_tag(p->iq,"password");
            }
        }else{
            log_debug(ZONE,"registration set request");
            if(p->to->user == NULL || xmlnode_get_tag_data(p->iq,"password") == NULL)
            {
                jutil_error(p->x, TERROR_NOTACCEPTABLE);
            }else if(js_user(si,p->to,NULL) != NULL){
                jutil_error(p->x, (terror){409,"Username Not Available"});
            }else if(!js_mapi_call(si, e_REGISTER, p, NULL, NULL)){
                jutil_error(p->x, TERROR_NOTIMPL);
            }

        }

    }else{ /* unknown namespace or other problem */
        jutil_error(p->x, TERROR_NOTACCEPTABLE);
    }

    /* restore the route packet */
    x = xmlnode_wrap(p->x,"route");
    xmlnode_put_attrib(x,"from",xmlnode_get_attrib(p->x,"from"));
    xmlnode_put_attrib(x,"to",xmlnode_get_attrib(p->x,"to"));
    xmlnode_put_attrib(x,"type",xmlnode_get_attrib(p->x,"route"));
    /* hide our uglies */
    xmlnode_hide_attrib(p->x,"from");
    xmlnode_hide_attrib(p->x,"to");
    xmlnode_hide_attrib(p->x,"route");
    /* reply */
    deliver(dpacket_new(x), si->i);
}

