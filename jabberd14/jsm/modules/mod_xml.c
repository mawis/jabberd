/* --------------------------------------------------------------------------
 *
 *  jabberd 1.4.4 GPL - XMPP/Jabber server implementation
 *
 *  Copyrights
 *
 *  Portions created by or assigned to Jabber.com, Inc. are
 *  Copyright (C) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 *  information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 *  Portions Copyright (C) 1998-1999 Jeremie Miller.
 *
 *
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  Special exception for linking jabberd 1.4.4 GPL with OpenSSL:
 *
 *  In addition, as a special exception, you are allowed to link the code
 *  of jabberd 1.4.4 GPL with the OpenSSL library (or with modified versions
 *  of OpenSSL that use the same license as OpenSSL), and distribute linked
 *  combinations including the two. You must obey the GNU General Public
 *  License in all respects for all of the code used other than OpenSSL.
 *  If you modify this file, you may extend this exception to your version
 *  of the file, but you are not obligated to do so. If you do not wish
 *  to do so, delete this exception statement from your version.
 *
 * --------------------------------------------------------------------------*/

#include "jsm.h"

/**
 * @file mod_xml.c
 * @brief handling jabber:iq:private (JEP-0049) requests as well as public storage (undocumented)
 *
 * This module implements the storage of private data by a client on the server using the
 * jabber:iq:private namespace documented in JEP-0049.
 *
 * The module also implements the storage of data, that will be accessible by any entity on
 * the Jabber network and the handling of requests by other users to this data.
 *
 * Requests are only handled if the requests are neither in a namespace starting with "jabber:"
 * nor in the "vcard-temp" namespace (which have to be implemented by other modules.
 * 
 * @todo Can we really rely on the namespace prefix to see if we should handle a request? New protocols don't use jabber: namespaces
 */

/**
 * callback that handles iq stanzas of the user itself (either set and get requests!)
 *
 * Store and retrieve public and private data by the user itself, but not data in the namespaces that start with 'jabber:' nor in
 * the 'vcard-temp' or 'http://jabberd.org/ns/storedpresence' namespaces.
 *
 * @todo Allow storage of 'jabber:' namespaces and the 'vcard-temp' namespace inside of private XML storage (JEP-0049 recommends this).
 * Not possible at present because we do not store the query element in the jabber:iq:private around the data in xdb and the user
 * would overwrite other stored data in this namespace.
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return M_IGNORE if it is not an iq stanza, M_PASS if the stanza has not been processed, M_HANDLED if the stanza has been handled
 */
mreturn mod_xml_set(mapi m, void *arg)
{
    xmlnode storedx, inx = m->packet->iq;
    char *ns = xmlnode_get_attrib(m->packet->iq,"xmlns");
    jid to = m->packet->to;
    int private = 0;
    jpacket jp;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;

    /* check for a private request */
    if(NSCHECK(m->packet->iq,NS_PRIVATE))
    {
        private = 1;
        inx = xmlnode_get_tag(m->packet->iq,"?xmlns");
        ns = xmlnode_get_attrib(inx,"xmlns");
        if(ns == NULL || strncmp(ns,"jabber:",7) == 0 || strcmp(ns,"vcard-temp") == 0 || strcmp(ns, NS_JABBERD_STOREDPRESENCE) == 0 || strcmp(ns, NS_JABBERD_HISTORY) == 0) {
	    /* uhoh, can't use jabber: namespaces inside iq:private! */
            jutil_error_xmpp(m->packet->x,(xterror){406,"Can't use jabber: namespaces inside iq:private","modify","not-acceptable"});
            js_session_to(m->s,m->packet);
            return M_HANDLED;
        }
    }else if(j_strncmp(ns,"jabber:",7) == 0 || j_strcmp(ns,"vcard-temp") == 0){ /* cant set public xml jabber: namespaces either! */
         return M_PASS;
    }

    /* if its to someone other than ourselves */
    if(to != NULL) {
	return M_PASS;
    } else {
	/* no to implies to ourselves */
	log_debug2(ZONE, LOGT_DELIVER, "handling user request %s",xmlnode2str(m->packet->iq));
        to = m->user->id;
    }

    switch(jpacket_subtype(m->packet))
    {
    case JPACKET__GET:
        log_debug2(ZONE, LOGT_DELIVER|LOGT_STORAGE, "handling get request for %s",ns);
        xmlnode_put_attrib(m->packet->x,"type","result");

        /* insert the chunk into the parent, that being either the iq:private container or the iq itself */
        if((storedx = xdb_get(m->si->xc, to, ns)) != NULL)
        {
            if(private) /* hack, ick! */
                xmlnode_hide_attrib(storedx,"j_private_flag");
            xmlnode_insert_tag_node(xmlnode_get_parent(inx), storedx);
            xmlnode_hide(inx);
        }

        /* send to the user */
        jpacket_reset(m->packet);
        js_session_to(m->s,m->packet);
        xmlnode_free(storedx);

        break;

    case JPACKET__SET:
        log_debug2(ZONE, LOGT_DELIVER|LOGT_STORAGE, "handling set request for %s with data %s",ns,xmlnode2str(inx));

        /* save the changes */
        if(private) /* hack, ick! */
            xmlnode_put_attrib(inx,"j_private_flag","1");
        if(xdb_set(m->si->xc, to, ns, inx))
            jutil_error_xmpp(m->packet->x,XTERROR_UNAVAIL);
        else
            jutil_iqresult(m->packet->x);

        /* insert the namespace on the list */
        storedx = xmlnode_new_tag("ns");
        xmlnode_insert_cdata(storedx,ns,-1);
        if(private)
            xmlnode_put_attrib(storedx,"type","private");
        xdb_act(m->si->xc, to, NS_XDBNSLIST, "insert", spools(m->packet->p,"ns=",ns,m->packet->p), storedx); /* match and replace any existing namespaces already listed */
        xmlnode_free(storedx);

        /* if it's to a resource that isn't browseable yet, fix that */
        if(to->resource != NULL)
        {
            if((storedx = xdb_get(m->si->xc, to, NS_BROWSE)) == NULL)
            { /* send an iq set w/ a generic browse item for this resource */
                jp = jpacket_new(jutil_iqnew(JPACKET__SET,NS_BROWSE));
                storedx = xmlnode_insert_tag(jp->iq, "item");
                xmlnode_put_attrib(storedx, "jid", jid_full(to));
                js_session_from(m->s, jp);
            }else{
                xmlnode_free(storedx);
            }
        }

        /* send to the user */
        jpacket_reset(m->packet);
        js_session_to(m->s,m->packet);

        break;

    default:
        return M_PASS;
    }

    return M_HANDLED;
}

/**
 * callback that handles iq stanzas from other users (either set and get requests)
 *
 * Requests in namespaces starting with "jabber:" and in the "vcard-temp" and "http://jabberd.org/ns/storedpresence"
 * namespaces are not handled, set-requests in other namespaces are explicitly rejected, get-requests are replied with information
 * stored in the user's xdb data if the data is not marked with a j_private_flag attribute of any value.
 *
 * @param m the mapi strcture
 * @param arg unused/ignored
 * @return M_IGNORED if it is no iq stanza, M_PASS if the stanza has not been handled, M_HANDLED if the stanza has been handled
 */
mreturn mod_xml_get(mapi m, void *arg)
{
    xmlnode xns;
    char *ns = xmlnode_get_attrib(m->packet->iq,"xmlns");

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(j_strncmp(ns,"jabber:",7) == 0 || j_strcmp(ns,"vcard-temp") == 0 || j_strcmp(ns, NS_JABBERD_STOREDPRESENCE) == 0 || j_strcmp(ns, NS_JABBERD_HISTORY) == 0)
	return M_PASS; /* only handle alternate namespaces */

    /* first, is this a valid request? */
    switch(jpacket_subtype(m->packet))
    {
    case JPACKET__RESULT:
    case JPACKET__ERROR:
        return M_PASS;
    case JPACKET__SET:
        js_bounce_xmpp(m->si,m->packet->x,XTERROR_FORBIDDEN);
        return M_HANDLED;
    }

    log_debug2(ZONE, LOGT_DELIVER|LOGT_STORAGE, "handling %s request for user %s",ns,jid_full(m->packet->to));

    /* get the foreign namespace */
    xns = xdb_get(m->si->xc, m->packet->to, ns);

    if(xmlnode_get_attrib(xns,"j_private_flag") != NULL)
    { /* uhoh, set from a private namespace */
        js_bounce_xmpp(m->si,m->packet->x,XTERROR_FORBIDDEN);
        return M_HANDLED;
    }

    /* reply to the request w/ any data */
    jutil_iqresult(m->packet->x);
    jpacket_reset(m->packet);
    xmlnode_insert_tag_node(m->packet->x,xns);
    js_deliver(m->si,m->packet);

    xmlnode_free(xns);
    return M_HANDLED;
}

/**
 * callback that gets notified on new sessions of a user
 *
 * will register mod_xml_set as callback for stanzas sent by the user itself
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return always M_PASS
 */
mreturn mod_xml_session(mapi m, void *arg)
{
    js_mapi_session(es_OUT,m->s,mod_xml_set,NULL);
    return M_PASS;
}

/**
 * init the mod_xml module by registering callbacks
 *
 * mod_xml_get will handle requests from other users
 *
 * mod_xml_session will register the mod_xml_set callback to process
 * requests from the user itself when the user starts a new session
 *
 * @param si the session manager instance
 */
void mod_xml(jsmi si)
{
    js_mapi_register(si,e_SESSION,mod_xml_session,NULL);
    js_mapi_register(si,e_OFFLINE,mod_xml_get,NULL);
}
