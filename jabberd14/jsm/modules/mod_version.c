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
#include <sys/utsname.h>

/**
 * @file mod_version.c
 * @brief implements handling of 'jabber:iq:version' (JEP-0092) in the session manager
 *
 * This session manager module implements the 'Software Version' protocol in the
 * session manager. It can be used to request which version of the Jabber server
 * (the version of the session manager) is running on which operating system version.
 * The information presented by this module is gathered automatically but the
 * administrator has the possibility to overwrite or hide this information.
 */


/**
 * @brief structure that holds precomputed strings for jabber:iq:version reply
 *
 * This structure keeps the strings used to build a reply for a version query.
 * Normally it is filled with collected information on the module startup, but
 * the administrator of the server is able to overwrite all fields in the session
 * manager configuration file.
 */
typedef struct
{
    pool p;		/**< memory pool used to build the strings in this structure */
    char *name;		/**< the natural-language name of the software */
    char *version;	/**< the specific version of the software */
    char *os;		/**< the operating system */
} _mod_version_i, *mod_version_i;

/**
 * callback function that handles jabber:iq:version queries
 *
 * All non iq stanzas are ignored by this function. Only queries in the jabber:iq:version
 * namespace are handled. Queries of type set are rejected, queries of type get are replied.
 *
 * @param m the mapi structure
 * @param arg pointer to the _mod_version_t structure of this module instance
 * @return M_IGNORED if not a iq stanza, M_PASS if stanza not handled, M_HANDLED if stanza has been handled
 */
mreturn mod_version_reply(mapi m, void *arg)
{
    mod_version_i mi = (mod_version_i)arg;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(!NSCHECK(m->packet->iq,NS_VERSION) || m->packet->to->resource != NULL) return M_PASS;

    /* first, is this a valid request? */
    if(jpacket_subtype(m->packet) != JPACKET__GET)
    {
        js_bounce_xmpp(m->si,m->packet->x,XTERROR_NOTALLOWED);
        return M_HANDLED;
    }

    log_debug2(ZONE, LOGT_DELIVER, "handling query from",jid_full(m->packet->from));

    jutil_iqresult(m->packet->x);
    xmlnode_put_attrib(xmlnode_insert_tag(m->packet->x,"query"),"xmlns",NS_VERSION);
    jpacket_reset(m->packet);
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"name"),mi->name,j_strlen(mi->name));
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"version"),mi->version,j_strlen(mi->version));
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"os"),mi->os,j_strlen(mi->os));
    
    js_deliver(m->si,m->packet);

    return M_HANDLED;
}

/**
 * free memory allocated by this module instance
 *
 * @param m the mapi structure
 * @param arg pointer to the _mod_version_t structure holding the data of this module instance
 * @return always M_PASS
 */
mreturn mod_version_shutdown(mapi m, void *arg)
{
    mod_version_i mi = (mod_version_i)arg;
    pool_free(mi->p);
    
    return M_PASS;
}

/**
 * register this module's callbacks in the session manager, allocate memory and precompute the replies
 *
 * @param si the session manager instance
 */
void mod_version(jsmi si)
{
    char *from;
    xmlnode x, config, name, version, os;
    pool p;
    mod_version_i mi;
    struct utsname un;

    p = pool_new();
    mi = pmalloco(p,sizeof(_mod_version_i));
    mi->p = p;

    /* get the values that should be reported by mod_version */
    uname(&un);
    config = js_config(si,"mod_version");
    name = xmlnode_get_tag(config, "name");
    version = xmlnode_get_tag(config, "version");
    os = xmlnode_get_tag(config, "os");

    mi->name = pstrdup(p, name ? xmlnode_get_data(name) : PACKAGE);
    if (version)
	mi->version = pstrdup(p, xmlnode_get_data(version));
    else
	/* knowing if the server has been compiled with IPv6 is very helpful
	 * for debugging dialback problems */
#ifdef WITH_IPV6
	mi->version = spools(p, VERSION, "-ipv6", p);
#else
    	mi->version = pstrdup(p, VERSION);
#endif
    if (os)
	mi->os = pstrdup(p, xmlnode_get_data(os));
    else if (xmlnode_get_tag(config, "no_os_version"))
	mi->os = pstrdup(p, un.sysname);
    else
	mi->os = spools(p, un.sysname, " ", un.release, p);


    js_mapi_register(si,e_SERVER,mod_version_reply,(void *)mi);
    js_mapi_register(si,e_SHUTDOWN,mod_version_shutdown,(void *)mi);

    /* check for updates */
    /* update.jabber.org is gone for a long time ...
    from = xmlnode_get_data(js_config(si,"update"));
    if(from == NULL) return;

    x = xmlnode_new_tag("presence");
    xmlnode_put_attrib(x,"from",from);
    xmlnode_put_attrib(x,"to","jsm@update.jabber.org/" VERSION);
    deliver(dpacket_new(x), si->i);
    */
}
