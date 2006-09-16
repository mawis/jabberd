/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "JOSL").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the JOSL. You
 * may obtain a copy of the JOSL at http://www.jabber.org/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the JOSL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the JOSL
 * for the specific language governing rights and limitations under the
 * JOSL.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 or later (the "GPL"), in which case
 * the provisions of the GPL are applicable instead of those above.  If you
 * wish to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the JOSL,
 * indicate your decision by deleting the provisions above and replace them
 * with the notice and other provisions required by the GPL.  If you do not
 * delete the provisions above, a recipient may use your version of this file
 * under either the JOSL or the GPL. 
 * 
 * 
 * --------------------------------------------------------------------------*/

/**
 * @file dialback.c
 * @brief main file of the dialback component implementing server to server connections
 *
 * This is the main file of the dialback component (module) of the Jabber server.
 *
 * The dialback protocol is documented in XMPP-core. This module only supports
 * identity verification using dialback, SASL is not supported.
 */

/*
DIALBACK (see XMPP core for a detailed description of this protocol):

A->B
    A: <db:result to=B from=A>...</db:result>

    B->A
        B: <db:verify to=A from=B id=asdf>...</db:verify>
        A: <db:verify type="valid" to=B from=A id=asdf/>

A->B
    B: <db:result type="valid" to=A from=B/>
*/

#include "dialback.h"

/**
 * helper structure used to pass an xmlnode as well as a jid when only one pointer can be passed
 */
typedef struct {
    xmlnode x;		/**< the xmlnode */
    jid id;		/**< the jid */
} _dialback_jid_with_xmlnode;

/**
 * check TLS and authentication settings for a s2s connection
 *
 * @param d the dialback instance
 * @param m the connection
 * @param server the host at the other end of the connection
 * @param is_outgoing 0 for an outgoing connection, 1 for an incoming connection
 * @param auth_type 0 for dialback, 1 for sasl
 * @param version 0 for a preXMPP stream, 1 for a XMPP1.0 stream
 * @return 0 if connection is not allowed, else connection is acceptable
 */
int dialback_check_settings(db d, mio m, const char *server, int is_outgoing, int auth_type, int version) {
    int required_protection = 0;
    int protection_level = mio_is_encrypted(m);
    const char *require_tls = xhash_get_by_domain(d->hosts_tls, server);
    const char *xmpp_version = version == -1 ? "unknown" : version == 0 ? "preXMPP" : "XMPP1.0";
    const char *auth = xhash_get_by_domain(d->hosts_auth, server);
   
    /* check the requirement of a TLS layer */
    if (j_strncmp(require_tls, "require", 7) == 0) {
	required_protection = 2;
    } else {
	required_protection = j_atoi(require_tls, 0);
    }
    log_debug2(ZONE, LOGT_IO, "requiring protection level %i for connection %s %s", required_protection, is_outgoing ? "to" : "from", server);
    if (protection_level < required_protection) {
	log_warn(d->i->id, "stopping dialback %s %s - stream protection level (%i) of established connection not good enough", is_outgoing ? "to" : "from", server, protection_level);
	mio_write(m, NULL, "<stream:error><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>We are configured to interconnect to your host only using a stream protected with STARTTLS or require a stronger encryption algorithm.</text></stream:error>", -1);
	mio_close(m);
	return 0;
    }

    /* check the required authentication mechanism */
    if (j_strcmp(auth, "db") == 0 && auth_type == 1) {
	log_warn(d->i->id, "closing connection %s %s: require dialback, but SASL has been used", is_outgoing ? "to" : "from", server);
	mio_write(m, NULL, "<stream:error><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>We are configured to not support SASL AUTH.</text></stream:error>", -1);
	mio_close(m);
	return 0;
    }
    if (j_strcmp(auth, "sasl") == 0 && auth_type == 0) {
	log_warn(d->i->id, "closing connection %s %s: require SASL, but dialback has been used", is_outgoing ? "to" : "from", server);
	mio_write(m, NULL, "<stream:error><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>We are configured to not support dialback. Well, we shouldn't even have tried or advertized dialback ...</text></stream:error>", -1);
	mio_close(m);
	return 0;
    }

    /* log the connection */
    if (protection_level < 1) {
	log_notice(d->i->id, "%s %s (unencrypted, no certificate, auth=%s, stream=%s)", is_outgoing ? "connected to" : "connection from", server, auth_type ? "sasl" : "db", xmpp_version);
    } else if (protection_level == 1) {
	log_notice(d->i->id, "%s %s (integrity protected, certificate is %s, auth=%s, stream=%s)", is_outgoing ? "connected to" : "connection from", server, mio_ssl_verify(m, server) ? "valid" : "invalid", auth_type ? "sasl" : "db", xmpp_version);
    } else {
	log_notice(d->i->id, "%s %s (encrypted: %i bit, certificate is %s, auth=%s, stream=%s)", is_outgoing ? "connected to" : "connection from", server, protection_level, mio_ssl_verify(m, server) ? "valid" : "invalid", auth_type ? "sasl" : "db", xmpp_version);
    }
    return 1;
}


/**
 * generate a random string (not thead-safe)
 *
 * This function generates a random ASCII string.
 *
 * @returns pointer to a string with 40 characters of random data
 */
char *dialback_randstr(void)
{
    static char ret[41];

    snprintf(ret, sizeof(ret), "%d", rand());
    shahash_r(ret,ret);
    return ret;
}

/**
 * convenience function to generate your dialback key (not thread-safe)
 *
 * @todo we don't use our own hostname to generate the dialback key, but xmpp-core
 * requires that we use both end's hostname to generate the key
 *
 * @param p the memory pool used
 * @param secret our dialback secret
 * @param to the destination of the stream
 * @param challenge the stream ID that should be verified
 * @return the dialback key
 */
char *dialback_merlin(pool p, char *secret, char *to, char *challenge)
{
    static char res[41];

    shahash_r(secret,                       res);
    shahash_r(spools(p, res, to, p),        res);
    shahash_r(spools(p, res, challenge, p), res);

    log_debug2(ZONE, LOGT_AUTH, "merlin casts his spell(%s+%s+%s) %s",secret,to,challenge,res);
    return res;
}

/**
 * write to a managed I/O connection and update the idle time values
 *
 * @param md structure holding the mio handle and the elements to keep track of idle time
 * @param x the xmlnode that should be written to the connection
 */
void dialback_miod_write(miod md, xmlnode x)
{
    md->count++;
    md->last = time(NULL);
    mio_write(md->m, x, NULL, -1);
}

/**
 * process a packet that has been read from a managed I/O connection and update the idle time values
 *
 * @param md structure holding the elements to keep track of idle time (and other elements)
 * @param x the xmlnode that has been read from the connection
 */
void dialback_miod_read(miod md, xmlnode x)
{
    jpacket jp = jpacket_new(x);

    /* only accept valid jpackets! */
    if(jp == NULL)
    {
        log_warn(md->d->i->id, "dropping invalid packet from server: %s",xmlnode_serialize_string(x, NULL, NULL, 0));
        xmlnode_free(x);
        return;
    }

    /* send it on! */
    md->count++;
    md->last = time(NULL);
    deliver(dpacket_new(x),md->d->i);
}

/**
 * create a new wrapper around a managed I/O connection to be able to keep track about idle connections and the state of the dialback
 *
 * @param d structure that holds the context of the dialback component instance 
 * @param m the managed I/O connection
 * @return pointer to the allocated miod structure
 */
miod dialback_miod_new(db d, mio m)
{
    miod md;

    md = pmalloco(m->p, sizeof(_miod));
    md->m = m;
    md->d = d;
    md->last = time(NULL);

    return md;
}

/**
 * @brief little wrapper to keep our hash tables in check
 *
 * This structure is used to pass everything that is needed to the _dialback_miod_hash_cleanup
 * callback as only one pointer can be passed to this function (it is registered as a pool cleaner function)
 * but we need multiple values
 */
struct miodc
{
    miod md; /**< structure holding the mio handle, idle time values and valid hosts */
    xht ht; /**< hash containing outgoing connections */
    jid key; /**< key of this connection in the ht hash, format "destination/source" */
};

/**
 * Unregister outgoing routings, that have been routed over this connection, that is closed now.
 *
 * clean up a hashtable entry containing this miod
 *
 * This function is called if the pool assocciated with the miod is freed.
 *
 * @param arg pointer to the miodc structure
 */
void _dialback_miod_hash_cleanup(void *arg)
{
    struct miodc *mdc = (struct miodc *)arg;
    if(xhash_get(mdc->ht,jid_full(mdc->key)) == mdc->md)
        xhash_zap(mdc->ht,jid_full(mdc->key));

    log_debug2(ZONE, LOGT_CLEANUP|LOGT_AUTH, "miod cleaning out socket %d with key %s to hash %X",mdc->md->m->fd, jid_full(mdc->key), mdc->ht);
    /* cool place for logging, eh? interesting way of detecting things too, *g* */
    if(mdc->ht == mdc->md->d->out_ok_db){
        unregister_instance(mdc->md->d->i, mdc->key->server); /* dynamic host resolution thingie */
        log_record(mdc->key->server, "out", "dialback", "%d %s %s", mdc->md->count, mio_ip(mdc->md->m), mdc->key->resource);
    }else if(mdc->ht == mdc->md->d->in_ok_db){
        log_record(mdc->key->server, "in", "dialback", "%d %s %s", mdc->md->count, mio_ip(mdc->md->m), mdc->key->resource);
    }
}

/**
 * registering a connection in the hash of outgoing connections
 *
 * @param md structure representing the outgoing connection
 * @param ht hash table containing all outgoing s2s connections
 * @param key destination with our source domain as the resource
 */
void dialback_miod_hash(miod md, xht ht, jid key)
{
    struct miodc *mdc;
    log_debug2(ZONE, LOGT_AUTH, "miod registering socket %d with key %s to hash %X",md->m->fd, jid_full(key), ht);
    mdc = pmalloco(md->m->p,sizeof(struct miodc));
    mdc->md = md;
    mdc->ht = ht;
    mdc->key = jid_new(md->m->p,jid_full(key));
    pool_cleanup(md->m->p, _dialback_miod_hash_cleanup, (void *)mdc);
    xhash_put(ht, jid_full(mdc->key), md);

    /* dns saver, only when registering on outgoing hosts dynamically */
    if(ht == md->d->out_ok_db)
    {
        dialback_ip_set(md->d, key, mio_ip(md->m)); /* save the ip since it won't be going through the dnsrv anymore */
        register_instance(md->d->i, key->server);
    }
}

/**
 * get the cached IP address for an external server
 *
 * @param d db structure which contains the context of the dialback component instance
 * @param host the host for which we need the IP address
 * @param ip the IP if the caller already knows it (conveniance parameter)
 * @return the IP of the external server
 */
char *dialback_ip_get(db d, jid host, char *ip)
{
    char *ret;
    if(host == NULL)
        return NULL;

    if(ip != NULL)
        return ip;

    ret =  pstrdup(host->p,xmlnode_get_attrib_ns((xmlnode)xhash_get(d->nscache,host->server),"i", NULL));
    log_debug2(ZONE, LOGT_IO, "returning cached ip %s for %s",ret,host->server);
    return ret;
}

/**
 * put an IP address in our DNS cache
 *
 * @param d db structure which contains the context of the dialback component instance
 * @param host the host for which we put the IP address
 * @param ip the IP address
 */
void dialback_ip_set(db d, jid host, char *ip)
{
    xmlnode cache, old;

    if(host == NULL || ip == NULL)
        return;

    /* first, get existing cache so we can dump it later */
    old = (xmlnode)xhash_get(d->nscache,host->server);

    /* new cache */
    cache = xmlnode_new_tag_ns("d", NULL, NS_JABBERD_WRAPPER);
    xmlnode_put_attrib_ns(cache, "h", NULL, NULL, host->server);
    xmlnode_put_attrib_ns(cache, "i", NULL, NULL, ip);
    xhash_put(d->nscache, xmlnode_get_attrib_ns(cache, "h", NULL), (void*)cache);
    log_debug2(ZONE, LOGT_IO, "cached ip %s for %s",ip,host->server);

    /* free any old entry that's been replaced */
    xmlnode_free(old);
}

/**
 * handle an incoming disco info request
 */
static void dialback_handle_discoinfo(db d, dpacket dp, xmlnode query, jid to) {
    const char *node = xmlnode_get_attrib_ns(query, "node", NULL);
    xmlnode result = NULL;
    xmlnode x = NULL;

    /* sanity check */
    if (to == NULL)
	return;

    /* we only reply get requests */
    /* XXX deny set requests */
    if (j_strcmp(xmlnode_get_attrib_ns(dp->x, "type", NULL), "get") != 0) {
	xmlnode_free(dp->x);
	return;
    }

    /* we have no items with nodes */
    /* XXX bounce with error */
    if (node != NULL) {
	xmlnode_free(dp->x);
	return;
    }

    /* generate basic result */
    jutil_tofrom(dp->x);
    xmlnode_put_attrib_ns(dp->x, "type", NULL, NULL, "result");
    xmlnode_hide(query);
    result = xmlnode_insert_tag_ns(dp->x, "query", NULL, NS_DISCO_INFO);

    if (to->user == NULL && to->resource == NULL) {
	x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "category", NULL, NULL, "component");
	xmlnode_put_attrib_ns(x, "type", NULL, NULL, "s2s");
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, "s2s component of " PACKAGE " " VERSION);

	x = xmlnode_insert_tag_ns(result, "feature", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "var", NULL, NULL, "xmllang");

	x = xmlnode_insert_tag_ns(result, "feature", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "var", NULL, NULL, "stringprep");

	x = xmlnode_insert_tag_ns(result, "feature", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "var", NULL, NULL, "urn:ietf:params:xml:ns:xmpp-tls#s2s");

	x = xmlnode_insert_tag_ns(result, "feature", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "var", NULL, NULL, "urn:ietf:params:xml:ns:xmpp-sasl#s2s");

#ifdef WITH_IPV6
	x = xmlnode_insert_tag_ns(result, "feature", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "var", NULL, NULL, "ipv6");
#endif
    } else if (j_strcmp(to->user, "out-established") == 0 && to->resource == NULL) {
	x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	xmlnode_put_attrib_ns(x, "type", NULL, NULL, "branch");
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, "established outgoing connections");
    } else if (j_strcmp(to->user, "out-connecting") == 0 && to->resource == NULL) {
	x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	xmlnode_put_attrib_ns(x, "type", NULL, NULL, "branch");
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, "connecting outgoing connections");
    } else if (j_strcmp(to->user, "in-established") == 0 && to->resource == NULL) {
	x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	xmlnode_put_attrib_ns(x, "type", NULL, NULL, "branch");
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, "established incoming connections");
    } else if (j_strcmp(to->user, "in-connecting") == 0 && to->resource == NULL) {
	x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	xmlnode_put_attrib_ns(x, "type", NULL, NULL, "branch");
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, "connecting incoming connections");
    } else if (j_strcmp(to->user, "out-established") == 0 && to->resource != NULL) {
	x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, to->resource);
    } else if (j_strcmp(to->user, "out-connecting") == 0 && to->resource != NULL) {
	x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, to->resource);
    } else if (j_strcmp(to->user, "in-established") == 0 && to->resource != NULL) {
	x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, to->resource);
    } else if (j_strcmp(to->user, "in-connecting") == 0 && to->resource != NULL) {
	x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, to->resource);
    }

    /* send result */
    deliver(dpacket_new(dp->x), d->i);
}

/**
 * iterate the xhash of established outgoing connections and add items for them to a disco#items query
 */
void _dialback_walk_out_established(xht h, const char *key, void *value, void *arg) {
    _dialback_jid_with_xmlnode *jx = (_dialback_jid_with_xmlnode*)arg;
    xmlnode item = NULL;

    /* sanity check */
    if (jx == NULL || value == NULL)
	return;

    /* create JID for the connection */
    jid_set(jx->id, key, JID_RESOURCE);

    /* add connection to the result */
    item = xmlnode_insert_tag_ns(jx->x, "item", NULL, NS_DISCO_ITEMS);
    xmlnode_put_attrib_ns(item, "name", NULL, NULL, key);
    xmlnode_put_attrib_ns(item, "jid", NULL, NULL, jid_full(jx->id));
}

/**
 * iterate the xhash of connecting outgoing connections and add items for them to a disco#items query
 */
void _dialback_walk_out_connecting(xht h, const char *key, void *value, void *arg) {
    _dialback_jid_with_xmlnode *jx = (_dialback_jid_with_xmlnode*)arg;
    xmlnode item = NULL;

    /* sanity check */
    if (jx == NULL || value == NULL)
	return;

    /* create JID for the connection */
    jid_set(jx->id, key, JID_RESOURCE);

    /* add connection to the result */
    item = xmlnode_insert_tag_ns(jx->x, "item", NULL, NS_DISCO_ITEMS);
    xmlnode_put_attrib_ns(item, "name", NULL, NULL, key);
    xmlnode_put_attrib_ns(item, "jid", NULL, NULL, jid_full(jx->id));
}

/**
 * iterate the xhash of established incomming connections and add items for them to a disco#items query
 */
void _dialback_walk_in_established(xht h, const char *key, void *value, void *arg) {
    _dialback_jid_with_xmlnode *jx = (_dialback_jid_with_xmlnode*)arg;
    xmlnode item = NULL;

    /* sanity check */
    if (jx == NULL || value == NULL)
	return;

    /* create JID for the connection */
    jid_set(jx->id, key, JID_RESOURCE);

    /* add connection to the result */
    item = xmlnode_insert_tag_ns(jx->x, "item", NULL, NS_DISCO_ITEMS);
    xmlnode_put_attrib_ns(item, "name", NULL, NULL, key);
    xmlnode_put_attrib_ns(item, "jid", NULL, NULL, jid_full(jx->id));
}

/**
 * iterate the xhash of connecting incomming connections and add items for them to a disco#items query
 */
void _dialback_walk_in_connecting(xht h, const char *key, void *value, void *arg) {
    _dialback_jid_with_xmlnode *jx = (_dialback_jid_with_xmlnode*)arg;
    xmlnode item = NULL;

    /* sanity check */
    if (jx == NULL || value == NULL)
	return;

    /* create JID for the connection */
    jid_set(jx->id, key, JID_RESOURCE);

    /* add connection to the result */
    item = xmlnode_insert_tag_ns(jx->x, "item", NULL, NS_DISCO_ITEMS);
    xmlnode_put_attrib_ns(item, "name", NULL, NULL, key);
    xmlnode_put_attrib_ns(item, "jid", NULL, NULL, jid_full(jx->id));
}

/**
 * handle an incoming disco items request
 */
static void dialback_handle_discoitems(db d, dpacket dp, xmlnode query, jid to) {
    const char *node = xmlnode_get_attrib_ns(query, "node", NULL);
    xmlnode result = NULL;
    xmlnode x = NULL;

    /* sanity check */
    if (to == NULL)
	return;

    /* we only reply get requests */
    /* XXX deny set requests */
    if (j_strcmp(xmlnode_get_attrib_ns(dp->x, "type", NULL), "get") != 0) {
	xmlnode_free(dp->x);
	return;
    }

    /* we have no items with nodes */
    /* XXX bounce with error */
    if (node != NULL) {
	xmlnode_free(dp->x);
	return;
    }

    /* generate basic result */
    jutil_tofrom(dp->x);
    xmlnode_put_attrib_ns(dp->x, "type", NULL, NULL, "result");
    xmlnode_hide(query);
    result = xmlnode_insert_tag_ns(dp->x, "query", NULL, NS_DISCO_ITEMS);


    if (to->user == NULL && to->resource == NULL) {
	if (acl_check_access(d->xc, "s2s", jid_new(xmlnode_pool(dp->x), xmlnode_get_attrib_ns(dp->x, "to", NULL)))) {
	    jid item_jid = jid_new(xmlnode_pool(dp->x), d->i->id);

	    jid_set(item_jid, "out-established", JID_USER);
	    x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, "established outgoing connections");
	    xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(item_jid));

	    jid_set(item_jid, "out-connecting", JID_USER);
	    x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, "connecting outgoing connections");
	    xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(item_jid));

	    jid_set(item_jid, "in-established", JID_USER);
	    x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, "established incoming connections");
	    xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(item_jid));

	    jid_set(item_jid, "in-connecting", JID_USER);
	    x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, "connecting incoming connections");
	    xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(item_jid));
	}
    } else if (j_strcmp(to->user, "out-established") == 0 && to->resource == NULL) {
	_dialback_jid_with_xmlnode jx;
	jx.x = result;
	jx.id = jid_new(xmlnode_pool(result), d->i->id);
	xhash_walk(d->out_ok_db, _dialback_walk_out_established, (void*)&jx);
    } else if (j_strcmp(to->user, "out-connecting") == 0 && to->resource == NULL) {
	_dialback_jid_with_xmlnode jx;
	jx.x = result;
	jx.id = jid_new(xmlnode_pool(result), d->i->id);
	xhash_walk(d->out_ok_db, _dialback_walk_out_connecting, (void*)&jx);
    } else if (j_strcmp(to->user, "in-established") == 0 && to->resource == NULL) {
	_dialback_jid_with_xmlnode jx;
	jx.x = result;
	jx.id = jid_new(xmlnode_pool(result), d->i->id);
	xhash_walk(d->out_ok_db, _dialback_walk_in_established, (void*)&jx);
    } else if (j_strcmp(to->user, "in-connecting") == 0 && to->resource == NULL) {
	_dialback_jid_with_xmlnode jx;
	jx.x = result;
	jx.id = jid_new(xmlnode_pool(result), d->i->id);
	xhash_walk(d->out_ok_db, _dialback_walk_in_connecting, (void*)&jx);
    }

    /* send result */
    deliver(dpacket_new(dp->x), d->i);
}

/**
 * phandler callback, send packets to another server
 *
 * This is where the dialback instance receives packets from the jabberd framework
 *
 * @param i the dialback instance we are running in
 * @param dp the dialback packet
 * @param arg pointer to the db structure with the context of the dialback component instance
 * @return always r_DONE
 */
result dialback_packets(instance i, dpacket dp, void *arg) {
    db d = (db)arg;
    xmlnode x = dp->x;
    char *ip = NULL;
    jid to = NULL;

    /* routes are from dnsrv w/ the needed ip */
    if (dp->type == p_ROUTE) {
        x = xmlnode_get_firstchild(x);
        ip = xmlnode_get_attrib_ns(dp->x,"ip", NULL);
    }

    /* all packets going to our "id" go to the incoming handler, 
     * it uses that id to send out db:verifies to other servers, 
     * and end up here when they bounce */
    if (j_strcmp(xmlnode_get_name(x), "verify") == 0 && j_strcmp(xmlnode_get_namespace(x), NS_DIALBACK) == 0) {
        xmlnode_put_attrib_ns(x, "to", NULL, NULL, xmlnode_get_attrib_ns(x, "ofrom", NULL));
        xmlnode_hide_attrib_ns(x, "ofrom", NULL); /* repair the addresses */
	xmlnode_hide_attrib_ns(x, "dnsqueryby", NULL); /* not needed anymore */
        dialback_in_verify(d, x);
        return r_DONE;
    }
    to = jid_new(xmlnode_pool(x), xmlnode_get_attrib_ns(x, "to", NULL));
    if (j_strcmp(to->server, d->i->id) == 0) {
	xmlnode x2 = NULL;

	/* some packets we do respond */
	x2 = xmlnode_get_list_item(xmlnode_get_tags(x, "discoinfo:query", d->std_ns_prefixes), 0);
	if (x2 != NULL) {
	    dialback_handle_discoinfo(d, dp, x2, to);
	    return r_DONE;
	}
	x2 = xmlnode_get_list_item(xmlnode_get_tags(x, "discoitems:query", d->std_ns_prefixes), 0);
	if (x2 != NULL) {
	    dialback_handle_discoitems(d, dp, x2, to);
	    return r_DONE;
	}

	xmlnode_free(x);
	return r_DONE;
    }

    dialback_out_packet(d, x, ip);
    return r_DONE;
}


/**
 * callback for walking each miod-value host hash tree, close connections that have been idle to long
 *
 * The timeout value is configured in the dialback component configuration using the <idletimeout/>
 * element.
 *
 * @param h the hash table containing all connections
 * @param key unused/ignored (the key of the value in the hash table)
 * @param data the value in the hash table = the structure holding the connection
 * @param arg unused/ignored
 */
void _dialback_beat_idle(xht h, const char *key, void *data, void *arg)
{
    miod md = (miod)data;
    if(((int)*(time_t*)arg - md->last) >= md->d->timeout_idle) {
        log_debug2(ZONE, LOGT_IO, "Idle Timeout on socket %d to %s",md->m->fd, mio_ip(md->m));
	mio_write(md->m, NULL, "<stream:error><connection-timeout xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xml:lang='en' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Closing an idle connection.</text></stream:error></stream:stream>", -1);
        mio_close(md->m);
    }
}

/**
 * initiate walking the hash of existing s2s connections to check if they have been idle to long
 *
 * called as a heartbeat function
 *
 * @param arg pointer to the structure holding the context of the dialback component instance
 * @return always r_DONE
 */
result dialback_beat_idle(void *arg)
{
    db d = (db)arg;
    time_t ttmp;

    log_debug2(ZONE, LOGT_EXECFLOW, "dialback idle check");
    time(&ttmp);
    xhash_walk(d->out_ok_db,_dialback_beat_idle,(void*)&ttmp);
    xhash_walk(d->in_ok_db,_dialback_beat_idle,(void*)&ttmp);
    return r_DONE;
}

/**
 * init and register the dialback component in the server
 *
 * @param i the jabber server's data about this instance
 * @param x xmlnode of this instances configuration (???)
 */
void dialback(instance i, xmlnode x)
{
    db d;
    xmlnode cfg, cur;
    xmlnode_list_item cur_item;
    struct karma k;
    int max;
    int rate_time, rate_points;
    int set_rate = 0, set_karma=0;

    log_debug2(ZONE, LOGT_INIT, "dialback loading");
    srand(time(NULL));


    d = pmalloco(i->p, sizeof(_db));

    /* get the config */
    d->xc = xdb_cache(i);
    cfg = xdb_get(d->xc, jid_new(xmlnode_pool(x), "config@-internal"), NS_JABBERD_CONFIG_DIALBACK);

    d->std_ns_prefixes = xhash_new(17);
    xhash_put(d->std_ns_prefixes, "", NS_SERVER);
    xhash_put(d->std_ns_prefixes, "stream", NS_STREAM);
    xhash_put(d->std_ns_prefixes, "db", NS_DIALBACK);
    xhash_put(d->std_ns_prefixes, "wrap", NS_JABBERD_WRAPPER);
    xhash_put(d->std_ns_prefixes, "tls", NS_XMPP_TLS);
    xhash_put(d->std_ns_prefixes, "sasl", NS_XMPP_SASL);
    xhash_put(d->std_ns_prefixes, "conf", NS_JABBERD_CONFIG_DIALBACK);
    xhash_put(d->std_ns_prefixes, "discoinfo", NS_DISCO_INFO);
    xhash_put(d->std_ns_prefixes, "discoitems", NS_DISCO_ITEMS);

    max = j_atoi(xmlnode_get_list_item_data(xmlnode_get_tags(cfg, "conf:maxhosts", d->std_ns_prefixes), 0), 997);
    d->nscache = xhash_new(max);
    pool_cleanup(i->p, (pool_cleaner)xhash_free, d->nscache);
    d->out_connecting = xhash_new(67);
    pool_cleanup(i->p, (pool_cleaner)xhash_free, d->out_connecting);
    d->out_ok_db = xhash_new(max);
    pool_cleanup(i->p, (pool_cleaner)xhash_free, d->out_ok_db);
    d->in_id = xhash_new(max);
    pool_cleanup(i->p, (pool_cleaner)xhash_free, d->in_id);
    d->in_ok_db = xhash_new(max);
    pool_cleanup(i->p, (pool_cleaner)xhash_free, d->in_ok_db);
    d->hosts_xmpp = xhash_new(max);
    d->hosts_tls = xhash_new(max);
    d->i = i;
    d->timeout_idle = j_atoi(xmlnode_get_list_item_data(xmlnode_get_tags(cfg, "conf:idletimeout", d->std_ns_prefixes), 0), 900);
    d->timeout_packets = j_atoi(xmlnode_get_list_item_data(xmlnode_get_tags(cfg, "conf:queuetimeout", d->std_ns_prefixes), 0), 30);
    d->secret = pstrdup(i->p, xmlnode_get_list_item_data(xmlnode_get_tags(cfg, "conf:secret", d->std_ns_prefixes), 0));
    if (d->secret == NULL) /* if there's no configured secret, make one on the fly */
        d->secret = pstrdup(i->p,dialback_randstr());

    /* Get rate info if it exists */
    cur = xmlnode_get_list_item(xmlnode_get_tags(cfg, "conf:rate", d->std_ns_prefixes), 0);
    if (cur != NULL) {
        rate_time   = j_atoi(xmlnode_get_attrib_ns(cur, "time", NULL), 0);
        rate_points = j_atoi(xmlnode_get_attrib_ns(cur, "points", NULL), 0);
        set_rate = 1; /* set to true */
    }

    /* Get karma info if it exists */
    cur = xmlnode_get_list_item(xmlnode_get_tags(cfg, "conf:karma", d->std_ns_prefixes), 0);
    if (cur != NULL) {
         k.val         = j_atoi(xmlnode_get_list_item_data(xmlnode_get_tags(cur, "conf:init", d->std_ns_prefixes), 0), KARMA_INIT);
         k.max         = j_atoi(xmlnode_get_list_item_data(xmlnode_get_tags(cur, "conf:max", d->std_ns_prefixes), 0), KARMA_MAX);
         k.inc         = j_atoi(xmlnode_get_list_item_data(xmlnode_get_tags(cur, "conf:inc", d->std_ns_prefixes), 0), KARMA_INC);
         k.dec         = j_atoi(xmlnode_get_list_item_data(xmlnode_get_tags(cur, "conf:dec", d->std_ns_prefixes), 0), KARMA_DEC);
         k.restore     = j_atoi(xmlnode_get_list_item_data(xmlnode_get_tags(cur, "conf:restore", d->std_ns_prefixes), 0), KARMA_RESTORE);
         k.penalty     = j_atoi(xmlnode_get_list_item_data(xmlnode_get_tags(cur, "conf:penalty", d->std_ns_prefixes), 0), KARMA_PENALTY);
         k.reset_meter = j_atoi(xmlnode_get_list_item_data(xmlnode_get_tags(cur, "conf:resetmeter", d->std_ns_prefixes), 0), KARMA_RESETMETER);
         set_karma = 1; /* set to true */
    }

    cur_item = xmlnode_get_tags(cfg, "conf:ip", d->std_ns_prefixes);
    if (cur_item != NULL) {
        for (; cur_item != NULL; cur_item = cur_item->next) {
            mio m;
            m = mio_listen(j_atoi(xmlnode_get_attrib_ns(cur_item->node, "port", NULL), 5269), xmlnode_get_data(cur_item->node), dialback_in_read, (void*)d, MIO_LISTEN_XML);
            if(m == NULL)
                return;
            /* Set New rate and points */
            if(set_rate == 1) mio_rate(m, rate_time, rate_points);
            /* Set New karma values */
            if(set_karma == 1) mio_karma2(m, &k);
        }
    } else {
	/* no special config, use defaults */
        mio m;
        m = mio_listen(5269,NULL,dialback_in_read,(void*)d, MIO_LISTEN_XML);
        if(m == NULL) return;
        /* Set New rate and points */
        if(set_rate == 1) mio_rate(m, rate_time, rate_points);
        /* Set New karma values */
        if(set_karma == 1) mio_karma2(m, &k);
    }

    /* check for hosts where we don't want to use XMPP streams or STARTTLS */
    for (cur_item = xmlnode_get_tags(cfg, "conf:host", d->std_ns_prefixes); cur_item != NULL; cur_item = cur_item->next) {
	char *xmpp = NULL;
	char *tls = NULL;
	char *auth = NULL;
	char *hostname = pstrdup(i->p, xmlnode_get_attrib_ns(cur_item->node, "name", NULL));

	/* the default setting is stored as a setting for '*' */
	if (hostname == NULL)
	    hostname = "*";

	xmpp = pstrdup(i->p, xmlnode_get_attrib_ns(cur_item->node, "xmpp", NULL));
	tls = pstrdup(i->p, xmlnode_get_attrib_ns(cur_item->node, "tls", NULL));
	auth = pstrdup(i->p, xmlnode_get_attrib_ns(cur_item->node, "auth", NULL));

	if (xmpp != NULL) {
	    xhash_put(d->hosts_xmpp, hostname, xmpp);
	}
	if (tls != NULL) {
	    xhash_put(d->hosts_tls, hostname, tls);
	}
	if (auth != NULL) {
	    xhash_put(d->hosts_auth, hostname, auth);
	}
    }

    register_phandler(i,o_DELIVER,dialback_packets,(void*)d);
    register_beat(d->timeout_idle, dialback_beat_idle, (void *)d);
    register_beat(d->timeout_packets, dialback_out_beat_packets, (void *)d);

    xmlnode_free(cfg);
}
