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
 * offline.c -- thread that handles data for other packets,
 * 	        which might be for offline or unknown users
 * --------------------------------------------------------------------------*/
#include "jsm.h"

void js_offline_main(void *arg)
{
    jpq q = (jpq)arg;
    udata user;

    /* performace hack, don't lookup the udata again */
    user = (udata)q->p->aux1;

    /* debug message */
    log_debug(ZONE,"THREAD:OFFLINE received %s's packet: %s",jid_full(user->id),xmlnode2str(q->p->x));

    /* let the modules handle the packet */
    if(!js_mapi_call(q->si, e_OFFLINE, q->p, user, NULL))
        js_bounce(q->si,q->p->x,TERROR_UNAVAIL);

    /* it can be cleaned up now */
    user->ref--;

}


