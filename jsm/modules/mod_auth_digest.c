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
#include <jsm.h>

mreturn mod_auth_digest_yum(mapi m, void *arg)
{
    spool s;
    char *sid;
    char *digest;
    char *passxdb;
    char *mydigest;
    xmlnode xdb;

    log_debug("mod_auth_digest","checking");

    if(jpacket_subtype(m->packet) == JPACKET__GET)
    { /* type=get means we flag that the server can do digest auth */
        xmlnode_insert_tag(m->packet->iq,"digest");
        return M_PASS;
    }

    if((digest = xmlnode_get_tag_data(m->packet->iq,"digest")) == NULL)
        return M_PASS;

    xdb = xdb_get(m->si->xc, m->user->id->server, m->user->id, NS_AUTH);
    passxdb = xmlnode_get_data(xdb);
    sid = xmlnode_get_attrib(xmlnode_get_tag(m->packet->iq,"digest"), "sid");

    /* Concat the stream id and password */
    /* SHA it up */
    log_debug("mod_auth_digest", "Got SID: %s", sid);
    s = spool_new(m->packet->p);
    spooler(s,sid,passxdb,s);

    mydigest = shahash(spool_print(s));

    /* don't need the xdb data anymore */
    xmlnode_free(xdb);

    log_debug("mod_auth_digest","comparing %s %s",digest,mydigest);

    if(digest == NULL || sid == NULL || mydigest == NULL) return M_PASS;

    if(j_strcasecmp(digest, mydigest) != 0)
        jutil_error(m->packet->x, TERROR_AUTH);
    else
        jutil_iqresult(m->packet->x);

    return M_HANDLED;
}

void mod_auth_digest(jsmi si)
{
    log_debug("mod_auth_digest","init");
    js_mapi_register(si,e_AUTH, mod_auth_digest_yum, NULL);
}
