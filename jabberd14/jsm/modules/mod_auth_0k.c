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
#include "jsm.h"

mreturn mod_auth_0k_go(mapi m, void *arg)
{
    char *token, *hash, *seqs;
    char *c_hash = NULL;
    int sequence = 0;
    xmlnode xdb;

    log_debug("mod_auth_0k","checking");

    if(jpacket_subtype(m->packet) == JPACKET__SET && (c_hash = xmlnode_get_tag_data(m->packet->iq,"hash")) == NULL)
        return M_PASS;

    /* first we need to see if this user is using 0k */
    xdb = xdb_get(m->si->xc, m->user->id, NS_AUTH_0K);
    if(xdb == NULL)
        return M_PASS;

    /* extract data */
    seqs = xmlnode_get_tag_data(xdb,"sequence");
    if(seqs != NULL)
    { /* get the current sequence as an int for the logic, and the client sequence as a decrement */
        sequence = atoi(seqs);
        if(sequence > 0)
            sprintf(seqs,"%d",sequence - 1);
    }
    token = xmlnode_get_tag_data(xdb,"token");
    hash = xmlnode_get_tag_data(xdb,"hash");

    if(jpacket_subtype(m->packet) == JPACKET__GET)
    { /* type=get, send back current 0k stuff if we've got it */
        if(hash != NULL && token != NULL && sequence > 0)
        {
            xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"sequence"),seqs,-1);
            xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"token"),token,-1);
        }
        xmlnode_free(xdb);
        return M_PASS;
    }

    log_debug("mod_auth_0k","got client hash %s for sequence %d and token %s",c_hash,sequence,token);

    /* only way this passes is if they got a valid get result from above, and had the pass to generate this new hash */
    if(j_strcmp(shahash(c_hash), hash) != 0)
    {
        jutil_error(m->packet->x, TERROR_AUTH);
    }else{
        /* store the new current hash/sequence */
        xmlnode_hide(xmlnode_get_tag(xdb,"sequence"));
        xmlnode_insert_cdata(xmlnode_insert_tag(xdb,"sequence"),seqs,-1);
        xmlnode_hide(xmlnode_get_tag(xdb,"hash"));
        xmlnode_insert_cdata(xmlnode_insert_tag(xdb,"hash"),c_hash,-1);

        xmlnode_put_attrib(xdb,"xmlns",NS_AUTH_0K);
        if(xdb_set(m->si->xc, m->user->id, NS_AUTH_0K, xdb))
            jutil_error(m->packet->x, TERROR_REQTIMEOUT);
        else
            jutil_iqresult(m->packet->x);
    }

    xmlnode_free(xdb); /* free xdb results */

    return M_HANDLED;
}

int mod_auth_0k_reset(mapi m, jid id, xmlnode xpass)
{
    char token[10];
    char seqs_default[] = "500";
    int sequence, i;
    char *seqs, *pass, hash[41];
    xmlnode x;

    log_debug("mod_auth_0k","resetting 0k variables");
    if((pass = xmlnode_get_data(xpass)) == NULL) return 1;

    /* in case there is no mod_auth_plain, we need to validate the account since xdb's iq:auth is used as flag that a user exists */
    if((x = xdb_get(m->si->xc, jid_user(id), NS_AUTH)) != NULL)
    { /* cool, they exist */
        xmlnode_free(x);
    }else{ /* make them exist with an empty password */
        x = xmlnode_new_tag_pool(xmlnode_pool(xpass),"password");
        xmlnode_put_attrib(x,"xmlns",NS_AUTH);
        if(xdb_set(m->si->xc, jid_user(id), NS_AUTH, x))
            return 1; /* uhoh */
    }


    /* figure out how many sequences to generate */
    seqs = xmlnode_get_tag_data(js_config(m->si, "mod_auth_0k"),"sequences");
    if(seqs == NULL)
        seqs = seqs_default;

    sequence = atoi(seqs);

    /* generate new token */
    sprintf(token,"%X",(int)time(NULL));

    /* first, hash the pass */
    shahash_r(pass,hash);
    /* next, hash that and the token */
    shahash_r(spools(xmlnode_pool(xpass),hash,token,xmlnode_pool(xpass)),hash);
    /* we've got hash0, now make as many as the sequence is */
    for(i = 0; i < sequence; i++, shahash_r(hash,hash));

    x = xmlnode_new_tag_pool(xmlnode_pool(xpass),"zerok");
    xmlnode_put_attrib(x,"xmlns",NS_AUTH_0K);
    xmlnode_insert_cdata(xmlnode_insert_tag(x,"hash"),hash,-1);
    xmlnode_insert_cdata(xmlnode_insert_tag(x,"token"),token,-1);
    xmlnode_insert_cdata(xmlnode_insert_tag(x,"sequence"),seqs,-1);
    return xdb_set(m->si->xc, jid_user(id), NS_AUTH_0K, x);
}

/* handle saving the password for registration */
mreturn mod_auth_0k_reg(mapi m, void *arg)
{
    if(jpacket_subtype(m->packet) != JPACKET__SET) return M_PASS;

    if(mod_auth_0k_reset(m,m->packet->to,xmlnode_get_tag(m->packet->iq,"password")))
    {
        jutil_error(m->packet->x,(terror){500,"Password Storage Failed"});
        return M_HANDLED;
    }

    return M_PASS;
}

/* handle password change requests from a session */
mreturn mod_auth_0k_server(mapi m, void *arg)
{
    xmlnode pass;

    /* pre-requisites */
    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(jpacket_subtype(m->packet) != JPACKET__SET || !NSCHECK(m->packet->iq,NS_REGISTER)) return M_PASS;
    if(m->user == NULL) return M_PASS;
    if((pass = xmlnode_get_tag(m->packet->iq,"password")) == NULL) return M_PASS;

    if(mod_auth_0k_reset(m,m->user->id,pass))
    {
        js_bounce(m->si,m->packet->x,(terror){500,"Password Storage Failed"});
        return M_HANDLED;
    }
    return M_PASS;
}

void mod_auth_0k(jsmi si)
{
    log_debug("mod_auth_0k","initing");

    js_mapi_register(si, e_AUTH, mod_auth_0k_go, NULL);
    js_mapi_register(si, e_SERVER, mod_auth_0k_server, NULL);
    if (js_config(si,"register") != NULL) js_mapi_register(si, e_REGISTER, mod_auth_0k_reg, NULL);
}
