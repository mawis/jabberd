/*
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2007 Matthias Wimmer
 *
 * This file is part of jabberd14.
 *
 * This software is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

/**
 * @file dialback.cc
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
    const char *require_tls = static_cast<char*>(xhash_get_by_domain(d->hosts_tls, server));
    const char *xmpp_version = version == -1 ? "unknown" : version == 0 ? "preXMPP" : "XMPP1.0";
    const char *auth = static_cast<char*>(xhash_get_by_domain(d->hosts_auth, server));
   
    /* check the requirement of a TLS layer */
    if (j_strncmp(require_tls, "force", 7) == 0) {
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
	log_notice(d->i->id, "%s %s (unencrypted, no cert, auth=%s, stream=%s, compression=none)", is_outgoing ? "connected to" : "connection from", server, auth_type ? "sasl" : "db", xmpp_version);
    } else if (protection_level == 1) {
	char certtype[32] = "no TLS";
	if (m->ssl) {
	    mio_tls_get_certtype(m, certtype, sizeof(certtype));
	}

	char compression[32] = "no TLS";
	if (m->ssl) {
	    mio_tls_get_compression(m, compression, sizeof(compression));
	}

	log_notice(d->i->id, "%s %s (integrity protected, %s cert is %s, auth=%s, stream=%s, compression=%s)", is_outgoing ? "connected to" : "connection from", server, certtype, mio_ssl_verify(m, server) ? "valid" : "invalid", auth_type ? "sasl" : "db", xmpp_version, compression);
    } else {
	char sl_characteristics[1024] = "no TLS";
	if (m->ssl) {
	    mio_tls_get_characteristics(m, sl_characteristics, sizeof(sl_characteristics));
	}

	char certtype[32] = "no TLS";
	if (m->ssl) {
	    mio_tls_get_certtype(m, certtype, sizeof(certtype));
	}

	char compression[32] = "no TLS";
	if (m->ssl) {
	    mio_tls_get_compression(m, compression, sizeof(compression));
	}

	log_notice(d->i->id, "%s %s (encrypted: %i b (%s), %s cert is %s, auth=%s, stream=%s, compression=%s)", is_outgoing ? "connected to" : "connection from", server, protection_level, m->ssl ? sl_characteristics : "no TLS", certtype, mio_ssl_verify(m, server) ? "valid" : "invalid", auth_type ? "sasl" : "db", xmpp_version, compression);
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
 * @note We generate a HMAC-SHA1 for the string "to from challenge" where
 * the challenge is the stream id generated by the destination host. As the
 * key for the HMAC-SHA1 we use the SHA1 hash of the secret.
 *
 * @param p the memory pool used
 * @param secret our dialback secret
 * @param to the destination of the stream
 * @param from the source host of the stream
 * @param challenge the stream ID that should be verified
 * @return the dialback key
 */
char *dialback_merlin(pool p, char *secret, char *to, char *from, char *challenge) {
    char *result = NULL;
    char *message = NULL;

    /* sanity check */
    if (p == NULL)
	return NULL;

    /* allocate memory for the result */
    result = static_cast<char*>(pmalloco(p, 41));

    /* generate the message, that has to be signed */
    message = spools(p, to, " ", from, " ", challenge, p);

    /* sign the message */
    hmac_sha1_ascii_r(secret, (unsigned char*)message, j_strlen(message), result);

    log_debug2(ZONE, LOGT_AUTH, "merlin casts his spell (%s - %s %s %s) %s", secret, to, from, challenge, result);

    return result;
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
        log_warn(md->d->i->id, "dropping invalid packet from server: %s",xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));
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

    md = static_cast<miod>(pmalloco(m->p, sizeof(_miod)));
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
    mdc = static_cast<struct miodc*>(pmalloco(md->m->p,sizeof(struct miodc)));
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
    jid requestor = NULL;
    int s2s_right = 0;
    const char* lang = xmlnode_get_lang(query);

    /* sanity check */
    if (to == NULL)
	return;

    /* we only reply get requests */
    /* XXX deny set requests */
    if (j_strcmp(xmlnode_get_attrib_ns(dp->x, "type", NULL), "get") != 0) {
	xmlnode_free(dp->x);
	return;
    }

    /* check the rights of the requesting user */
    requestor = jid_new(xmlnode_pool(dp->x), xmlnode_get_attrib_ns(dp->x, "from", NULL));
    s2s_right = acl_check_access(d->xc, "s2s", requestor);

    /* generate basic result */
    jutil_tofrom(dp->x);
    xmlnode_put_attrib_ns(dp->x, "type", NULL, NULL, "result");
    xmlnode_hide(query);
    result = xmlnode_insert_tag_ns(dp->x, "query", NULL, NS_DISCO_INFO);

    if (s2s_right && to->user == NULL && to->resource == NULL && node == NULL) {
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
    } else if (s2s_right && j_strcmp(to->user, "out-established") == 0 && to->resource == NULL && node == NULL) {
	x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	xmlnode_put_attrib_ns(x, "type", NULL, NULL, "branch");
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("established outgoing connections")));
    } else if (s2s_right && j_strcmp(to->user, "out-connecting") == 0 && to->resource == NULL && node == NULL) {
	x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	xmlnode_put_attrib_ns(x, "type", NULL, NULL, "branch");
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("connecting outgoing connections")));
    } else if (s2s_right && j_strcmp(to->user, "in-established") == 0 && to->resource == NULL && node == NULL) {
	x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	xmlnode_put_attrib_ns(x, "type", NULL, NULL, "branch");
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("established incoming connections")));
    } else if (s2s_right && j_strcmp(to->user, "in-connecting") == 0 && to->resource == NULL && node == NULL) {
	x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	xmlnode_put_attrib_ns(x, "type", NULL, NULL, "branch");
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("connecting incoming connections")));
    } else if (s2s_right && j_strcmp(to->user, "out-established") == 0 && to->resource != NULL && node == NULL) {
	x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	xmlnode_put_attrib_ns(x, "type", NULL, NULL, "branch");
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, to->resource);
    } else if (s2s_right && j_strcmp(to->user, "out-established") == 0 && to->resource != NULL && j_strcmp(node, "last") == 0) {
	char last_time[32];
	miod md = static_cast<miod>(xhash_get(d->out_ok_db, to->resource));

	if (md == NULL) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("-- connection gone --")));
	} else {
	    struct tm last_utc;
	    time_t last = md->last;

	    if (gmtime_r(&last, &last_utc)) {
		char last_str[36];

		snprintf(last_str, sizeof(last_str), "%s %d-%02d-%02d %02d:%02d:%02d UTC", messages_get(lang, N_("Last used:")),
			1900+last_utc.tm_year, last_utc.tm_mon+1, last_utc.tm_mday, last_utc.tm_hour, last_utc.tm_min, last_utc.tm_sec);

		x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
		xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
		xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
		xmlnode_put_attrib_ns(x, "name", NULL, NULL, last_str);
	    }
	}
    } else if (s2s_right && j_strcmp(to->user, "out-established") == 0 && to->resource != NULL && j_strcmp(node, "count") == 0) {
	miod md = static_cast<miod>(xhash_get(d->out_ok_db, to->resource));

	if (md == NULL) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("-- connection gone --")));
	} else {
	    char name_str[36];

	    snprintf(name_str, sizeof(name_str), "%s %d", messages_get(lang, N_("Stanza count:")), md->count);

	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, name_str);
	}
    } else if (s2s_right && j_strcmp(to->user, "out-established") == 0 && to->resource != NULL && j_strcmp(node, "ip") == 0) {
	miod md = static_cast<miod>(xhash_get(d->out_ok_db, to->resource));

	if (md == NULL || md->m == NULL) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("-- connection gone --")));
	} else {
	    char ip_str[128];

	    snprintf(ip_str, sizeof(ip_str), "%s %s=%s;%d %s=%s;%d %s=%s",
		    messages_get(lang, N_("IP/port:")),
		    messages_get(lang, N_("local")),
		    md->m->our_ip,
		    md->m->our_port,
		    messages_get(lang, N_("remote")),
		    md->m->peer_ip,
		    md->m->peer_port,
		    messages_get(lang, N_("tls")),
		    md->m->ssl == NULL ? messages_get(lang, N_("no")) : messages_get(lang, N_("yes")));

	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, ip_str);
	}
    } else if (s2s_right && j_strcmp(to->user, "out-connecting") == 0 && to->resource != NULL && node == NULL) {
	x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, to->resource);
    } else if (s2s_right && j_strcmp(to->user, "out-connecting") == 0 && to->resource != NULL && node != NULL) {
	dboc dc = static_cast<dboc>(xhash_get(d->out_connecting, to->resource));

	if (dc == NULL) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("-- connection gone or now established --")));
	} else if (j_strcmp(node, "ip") == 0) {
	    char ip_str[128];

	    if (dc->m != NULL) {
		snprintf(ip_str, sizeof(ip_str), "%s: %s=%s;%d %s=%s;%d %s=%s",
			messages_get(lang, N_("IP/port:")),
			messages_get(lang, N_("local")),
			dc->m->our_ip, dc->m->our_port,
			messages_get(lang, N_("remote")),
			dc->m->peer_ip, dc->m->peer_port,
			messages_get(lang, N_("tls")),
			dc->m->ssl == NULL ? messages_get(lang, N_("no")) : messages_get(lang, N_("yes")));
	    } else {
		snprintf(ip_str, sizeof(ip_str), messages_get(lang, N_("IP/port: no current connection")));
	    }

	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, ip_str);
	} else if (j_strcmp(node, "last") == 0) {
	    struct tm last_utc;
	    time_t last = dc->stamp;

	    if (gmtime_r(&last, &last_utc)) {
		char last_str[64];

		snprintf(last_str, sizeof(last_str), "%s %d-%02d-%02d %02d:%02d:%02d UTC", messages_get(lang, N_("Connection start:")),
			1900+last_utc.tm_year, last_utc.tm_mon+1, last_utc.tm_mday, last_utc.tm_hour, last_utc.tm_min, last_utc.tm_sec);

		x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
		xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
		xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
		xmlnode_put_attrib_ns(x, "name", NULL, NULL, last_str);
	    }
	} else if (j_strcmp(node, "xmppversion") == 0) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, dc->xmpp_version < 0 ? messages_get(lang, N_("XMPP version: unknown")) : dc->xmpp_version ? messages_get(lang, N_("XMPP version: 1.0")) : messages_get(lang, N_("XMPP version: 0.9")));
	} else if (j_strcmp(node, "pendingip") == 0) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, spools(xmlnode_pool(result), messages_get(lang, N_("Pending IPs: ")), dc->ip ? dc->ip : messages_get(lang, N_("no more other IPs will be tried")), xmlnode_pool(result)));
	} else if (j_strcmp(node, "id") == 0) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, spools(xmlnode_pool(result), messages_get(lang, N_("Stream ID: ")), dc->stream_id, xmlnode_pool(result)));
	} else if (j_strcmp(node, "dbstate") == 0) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, spools(xmlnode_pool(result), messages_get(lang, N_("Dialback state: ")),
			dc->db_state == not_requested ? messages_get(lang, N_("no dialback request, just sending verifies")) :
			dc->db_state == could_request ? messages_get(lang, N_("we could send dialback requests, if we want to")) :
			dc->db_state == want_request ? messages_get(lang, N_("we want to send dialback requests, but cannot do that yet")) :
			dc->db_state == sent_request ? messages_get(lang, N_("we have sent a dialback request")) : messages_get(lang, N_("invalid")), xmlnode_pool(result)));
	} else if (j_strcmp(node, "connstate") == 0) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, spools(xmlnode_pool(result), messages_get(lang, N_("Connection state: ")),
			dc->connection_state == created ? messages_get(lang, N_("created, not yet started to connect")) :
			dc->connection_state == connecting ? messages_get(lang, N_("we started to connect, no connection yet")) :
			dc->connection_state == connected ? messages_get(lang, N_("connected to the other host")) :
			dc->connection_state == got_streamroot ? messages_get(lang, N_("we got peer's stream root")) :
			dc->connection_state == waiting_features ? messages_get(lang, N_("we are waiting for stream features")) :
			dc->connection_state == got_features ? messages_get(lang, N_("we got the stream features")) :
			dc->connection_state == sent_db_request ? messages_get(lang, N_("we sent out a dialback request")) :
			dc->connection_state == db_succeeded ? messages_get(lang, N_("we had success with our dialback request")) :
			dc->connection_state == db_failed ? messages_get(lang, N_("dialback failed")) :
			dc->connection_state == sasl_started ? messages_get(lang, N_("we started to authenticate using sasl")) :
			dc->connection_state == sasl_fail ? messages_get(lang, N_("there was a SASL authentication failure")) :
			dc->connection_state == sasl_success ? messages_get(lang, N_("successfully authenticated using SASL")) : messages_get(lang, N_("invalid")), xmlnode_pool(result)));
	} else if (j_strcmp(node, "dialback") == 0) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, spools( xmlnode_pool(result), messages_get(lang, N_("Dialback: ")), dc->flags.db ?  messages_get(lang, N_("supported by peer")) : messages_get(lang, N_("unsupported by peer")), xmlnode_pool(result)));
	} else if (j_strcmp(node, "connectresults") == 0) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, spools(xmlnode_pool(result), messages_get(lang, N_("Connection results: ")), spool_print(dc->connect_results), xmlnode_pool(result)));
	} else if (j_strcmp(node, "failedsettings") == 0) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, spools(xmlnode_pool(result), messages_get(lang, N_("Dropped because of settings: ")), dc->settings_failed ? messages_get(lang, N_("yes")) : messages_get(lang, N_("no")), xmlnode_pool(result)));
	} else if (j_strcmp(node, "verifies") == 0) {
	    int count = 0;
	    xmlnode iter = NULL;
	    char count_str[16];

	    for (iter = xmlnode_get_firstchild(dc->verifies); iter != NULL; iter = xmlnode_get_nextsibling(iter)) {
		count++;
	    }
	    snprintf(count_str, sizeof(count_str), "%d", count);

	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, spools(xmlnode_pool(result), messages_get(lang, N_("Pending verifies: ")), count_str, xmlnode_pool(result)));
	} else if (j_strcmp(node, "pendingstanzas") == 0) {
	    int count = 0;
	    dboq iter = NULL;
	    char count_str[16];

	    for (iter = dc->q; iter != NULL; iter = iter->next) {
		count++;
	    }
	    snprintf(count_str, sizeof(count_str), "%d", count);

	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, spools(xmlnode_pool(result), messages_get(lang, N_("Pending stanzas: ")), count_str, xmlnode_pool(result)));
	}
    } else if (s2s_right && j_strcmp(to->user, "in-established") == 0 && to->resource != NULL && node == NULL) {
	x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, to->resource);
    } else if (s2s_right && j_strcmp(to->user, "in-established") == 0 && to->resource != NULL && j_strcmp(node, "last") == 0) {
	char last_time[32];
	miod md = static_cast<miod>(xhash_get(d->in_ok_db, to->resource));

	if (md == NULL) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("-- connection gone --")));
	} else {
	    struct tm last_utc;
	    time_t last = md->last;

	    if (gmtime_r(&last, &last_utc)) {
		char last_str[36];

		snprintf(last_str, sizeof(last_str), "%s: %d-%02d-%02d %02d:%02d:%02d UTC", messages_get(lang, N_("Last used:")),
			1900+last_utc.tm_year, last_utc.tm_mon+1, last_utc.tm_mday, last_utc.tm_hour, last_utc.tm_min, last_utc.tm_sec);

		x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
		xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
		xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
		xmlnode_put_attrib_ns(x, "name", NULL, NULL, last_str);
	    }
	}
    } else if (s2s_right && j_strcmp(to->user, "in-established") == 0 && to->resource != NULL && j_strcmp(node, "count") == 0) {
	miod md = static_cast<miod>(xhash_get(d->in_ok_db, to->resource));

	if (md == NULL) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("-- connection gone --")));
	} else {
	    char name_str[36];

	    snprintf(name_str, sizeof(name_str), "%s %d", messages_get(lang, N_("Stanza count:")), md->count);

	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, name_str);
	}
    } else if (s2s_right && j_strcmp(to->user, "in-established") == 0 && to->resource != NULL && j_strcmp(node, "ip") == 0) {
	miod md = static_cast<miod>(xhash_get(d->in_ok_db, to->resource));

	if (md == NULL || md->m == NULL) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("-- connection gone --")));
	} else {
	    char ip_str[128];

	    snprintf(ip_str, sizeof(ip_str), "%s %s=%s;%d %s=%s;%d %s=%s",
		    messages_get(lang, N_("IP/port:")),
		    messages_get(lang, N_("local")),
		    md->m->our_ip, md->m->our_port,
		    messages_get(lang, N_("remote")),
		    md->m->peer_ip, md->m->peer_port,
		    messages_get(lang, N_("tls")),
		    md->m->ssl == NULL ? messages_get(lang, N_("no")) : messages_get(lang, N_("yes")));

	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, ip_str);
	}
    } else if (s2s_right && j_strcmp(to->user, "in-connecting") == 0 && to->resource != NULL && node == NULL) {
	x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, to->resource);
    } else if (s2s_right && j_strcmp(to->user, "in-connecting") == 0 && to->resource != NULL && node != NULL) {
	dbic c = static_cast<dbic>(xhash_get(d->in_id, to->resource));

	if (c == NULL) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("-- connection gone or now established --")));
	} else if (j_strcmp(node, "ip") == 0) {
	    char ip_str[128];

	    if (c->m != NULL) {
		snprintf(ip_str, sizeof(ip_str), "%s %s=%s;%d %s=%s;%d %s=%s",
			messages_get(lang, N_("IP/port:")),
			messages_get(lang, N_("local")),
			c->m->our_ip, c->m->our_port,
			messages_get(lang, N_("remote")),
			c->m->peer_ip, c->m->peer_port,
			messages_get(lang, N_("tls")),
			c->m->ssl == NULL ? messages_get(lang, N_("no")) : messages_get(lang, N_("yes")));
	    } else {
		snprintf(ip_str, sizeof(ip_str), messages_get(lang, N_("IP/port: no current connection")));
	    }

	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, ip_str);
	} else if (j_strcmp(node, "addresses") == 0) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, spools(xmlnode_pool(result), messages_get(lang, N_("Addresses:")), " ", messages_get(lang, N_("local")), "=", c->we_domain, ", ", messages_get(lang, N_("peer")), "=", c->other_domain, xmlnode_pool(result)));
	} else if (j_strcmp(node, "xmppversion") == 0) {
	    x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
	    xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
	    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, c->xmpp_version < 0 ? messages_get(lang, N_("XMPP version: unknown")) : c->xmpp_version ? messages_get(lang, N_("XMPP version: 1.0")) : messages_get(lang, N_("XMPP version: 0.9")));
	} else if (j_strcmp(node, "last") == 0) {
	    struct tm last_utc;
	    time_t last = c->stamp;

	    if (gmtime_r(&last, &last_utc)) {
		char last_str[64];

		snprintf(last_str, sizeof(last_str), "%s %d-%02d-%02d %02d:%02d:%02d UTC", messages_get(lang, N_("Connection start:")),
			1900+last_utc.tm_year, last_utc.tm_mon+1, last_utc.tm_mday, last_utc.tm_hour, last_utc.tm_min, last_utc.tm_sec);

		x = xmlnode_insert_tag_ns(result, "identity", NULL, NS_DISCO_INFO);
		xmlnode_put_attrib_ns(x, "category", NULL, NULL, "hierarchy");
		xmlnode_put_attrib_ns(x, "type", NULL, NULL, "leaf");
		xmlnode_put_attrib_ns(x, "name", NULL, NULL, last_str);
	    }
	}
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
    jid requestor = NULL;
    int s2s_right = 0;
    const char* lang = NULL;

    /* sanity check */
    if (to == NULL)
	return;

    /* we only reply get requests */
    /* XXX deny set requests */
    if (j_strcmp(xmlnode_get_attrib_ns(dp->x, "type", NULL), "get") != 0) {
	xmlnode_free(dp->x);
	return;
    }

    /* check the rights of the requesting user */
    requestor = jid_new(xmlnode_pool(dp->x), xmlnode_get_attrib_ns(dp->x, "from", NULL));
    s2s_right = acl_check_access(d->xc, "s2s", requestor);

    /* generate basic result */
    jutil_tofrom(dp->x);
    xmlnode_put_attrib_ns(dp->x, "type", NULL, NULL, "result");
    xmlnode_hide(query);
    result = xmlnode_insert_tag_ns(dp->x, "query", NULL, NS_DISCO_ITEMS);
    lang = xmlnode_get_lang(dp->x);

    if (to->user == NULL && to->resource == NULL && node == NULL && s2s_right) {
	jid item_jid = jid_new(xmlnode_pool(dp->x), d->i->id);

	jid_set(item_jid, "out-established", JID_USER);
	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("established outgoing connections")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(item_jid));

	jid_set(item_jid, "out-connecting", JID_USER);
	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("connecting outgoing connections")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(item_jid));

	jid_set(item_jid, "in-established", JID_USER);
	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("established incoming connections")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(item_jid));

	jid_set(item_jid, "in-connecting", JID_USER);
	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("connecting incoming connections")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(item_jid));
    } else if (s2s_right && j_strcmp(to->user, "out-established") == 0 && to->resource == NULL && node == NULL) {
	_dialback_jid_with_xmlnode jx;
	jx.x = result;
	jx.id = jid_new(xmlnode_pool(result), d->i->id);
	jid_set(jx.id, "out-established", JID_USER);
	xhash_walk(d->out_ok_db, _dialback_walk_out_established, (void*)&jx);
    } else if (s2s_right && j_strcmp(to->user, "out-established") == 0 && to->resource != NULL && node == NULL) {
	jid other_server = jid_new(xmlnode_pool(result), to->resource);

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("Last used")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "last");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("Stanza count")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "count");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("IP/port")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "ip");

	if (other_server != NULL) {
	    x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, other_server->server);
	    xmlnode_put_attrib_ns(x, "jid", NULL, NULL, other_server->server);
	}
    } else if (s2s_right && j_strcmp(to->user, "out-connecting") == 0 && to->resource == NULL && node == NULL) {
	_dialback_jid_with_xmlnode jx;
	jx.x = result;
	jx.id = jid_new(xmlnode_pool(result), d->i->id);
	jid_set(jx.id, "out-connecting", JID_USER);
	xhash_walk(d->out_connecting, _dialback_walk_out_connecting, (void*)&jx);
    } else if (s2s_right && j_strcmp(to->user, "out-connecting") == 0 && to->resource != NULL && node == NULL) {
	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("Connection start")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "last");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("IP/port")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "ip");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("XMPP version")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "xmppversion");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("Pending IPs")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "pendingip");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("Dialback verifies")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "verifies");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("Pending stanzas")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "pendingstanzas");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("Dropped because of settings")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "failedsettings");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("Stream ID")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "id");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("Dialback state")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "dbstate");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("Connection state")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "connstate");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("Connect results")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "connectresults");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("Dialback")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "dialback");
    } else if (s2s_right && j_strcmp(to->user, "in-established") == 0 && to->resource == NULL && node == NULL) {
	_dialback_jid_with_xmlnode jx;
	jx.x = result;
	jx.id = jid_new(xmlnode_pool(result), d->i->id);
	jid_set(jx.id, "in-established", JID_USER);
	xhash_walk(d->in_ok_db, _dialback_walk_in_established, (void*)&jx);
    } else if (s2s_right && j_strcmp(to->user, "in-established") == 0 && to->resource != NULL && node == NULL) {
	jid other_server = jid_new(xmlnode_pool(result), to->resource);

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("Last used")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "last");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("Stanza count")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "count");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("IP/port")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "ip");

	if (other_server != NULL) {
	    x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	    xmlnode_put_attrib_ns(x, "name", NULL, NULL, other_server->resource);
	    xmlnode_put_attrib_ns(x, "jid", NULL, NULL, other_server->resource);
	}
    } else if (s2s_right && j_strcmp(to->user, "in-connecting") == 0 && to->resource == NULL && node == NULL) {
	_dialback_jid_with_xmlnode jx;
	jx.x = result;
	jx.id = jid_new(xmlnode_pool(result), d->i->id);
	jid_set(jx.id, "in-connecting", JID_USER);
	xhash_walk(d->in_id, _dialback_walk_in_connecting, (void*)&jx);
    } else if (s2s_right && j_strcmp(to->user, "in-connecting") == 0 && to->resource != NULL && node == NULL) {
	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("IP/port")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "ip");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("Addresses")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "addresses");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("XMPP version")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "xmppversion");

	x = xmlnode_insert_tag_ns(result, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(x, "name", NULL, NULL, messages_get(lang, N_("Connection start")));
	xmlnode_put_attrib_ns(x, "jid", NULL, NULL, jid_full(to));
	xmlnode_put_attrib_ns(x, "node", NULL, NULL, "last");
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
 * The timeout value is configured in the dialback component configuration using the &lt;idletimeout/&gt;
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
	mio_write(md->m, NULL, "</stream:stream>", -1);
        mio_close(md->m);
    }
}

/**
 * callback for walking incoming connections, that are not authorized yet, checking for timeotus
 *
 * @param h the hash table containing all connections
 * @param key unused/ignored (the key of the value in the hash table)
 * @param data the value in the hash table = the structure holding the connection
 * @param arg unused/ignored
 */
void _dialback_beat_in_idle(xht h, const char *key, void *data, void *arg) {
    dbic c = (dbic)data;
    if(((int)*(time_t*)arg - c->stamp) >= c->d->timeout_auth) {
        log_debug2(ZONE, LOGT_IO, "Idle Timeout on socket %d to %s", c->m->fd, mio_ip(c->m));
	mio_write(c->m, NULL, "</stream:stream>", -1);
        mio_close(c->m);
    }
}

/**
 * callback for walking outgoing connections, that are not authorized yet, checking for timeotus
 *
 * @param h the hash table containing all connections
 * @param key unused/ignored (the key of the value in the hash table)
 * @param data the value in the hash table = the structure holding the connection
 * @param arg unused/ignored
 */
void _dialback_beat_out_idle(xht h, const char *key, void *data, void *arg) {
    dboc c = (dboc)data;
    if(((int)*(time_t*)arg - c->stamp) >= c->d->timeout_auth) {
        log_debug2(ZONE, LOGT_IO, "Idle Timeout on socket %d to %s", c->m->fd, mio_ip(c->m));
	mio_write(c->m, NULL, "</stream:stream>", -1);
        mio_close(c->m);
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
    xhash_walk(d->in_id, _dialback_beat_in_idle, (void*)&ttmp);
    xhash_walk(d->out_connecting, _dialback_beat_out_idle, (void*)&ttmp);
    return r_DONE;
}

/**
 * we pass a token in the stream root to identify a looping connection to ourself. This generated the token of the server.
 *
 * @param d the dialback instance
 * @return the token to use
 */
const char* dialback_get_loopcheck_token(db d) {
    static char hmac[41];
    static int hmac_done = 0;

    if (!hmac_done) {
	hmac_sha1_ascii_r(d->secret, (unsigned char*)"loopcheck", 9, hmac);
	hmac_done = 1;
    }
    return hmac;
}

/**
 * init and register the dialback component in the server
 *
 * @param i the jabber server's data about this instance
 * @param x xmlnode of this instances configuration (???)
 */
extern "C" void dialback(instance i, xmlnode x) {
    db d;
    xmlnode cfg, cur;
    xmlnode_list_item cur_item;
    struct karma k;
    int max;
    int rate_time, rate_points;
    int set_rate = 0, set_karma=0;

    log_debug2(ZONE, LOGT_INIT, "dialback loading");
    srand(time(NULL));


    d = static_cast<db>(pmalloco(i->p, sizeof(_db)));

    /* get the config */
    d->xc = xdb_cache(i);
    cfg = xdb_get(d->xc, jid_new(xmlnode_pool(x), "config@-internal"), NS_JABBERD_CONFIG_DIALBACK);

    d->std_ns_prefixes = xhash_new(17);
    xhash_put(d->std_ns_prefixes, "", const_cast<char*>(NS_SERVER));
    xhash_put(d->std_ns_prefixes, "stream", const_cast<char*>(NS_STREAM));
    xhash_put(d->std_ns_prefixes, "db", const_cast<char*>(NS_DIALBACK));
    xhash_put(d->std_ns_prefixes, "wrap", const_cast<char*>(NS_JABBERD_WRAPPER));
    xhash_put(d->std_ns_prefixes, "tls", const_cast<char*>(NS_XMPP_TLS));
    xhash_put(d->std_ns_prefixes, "sasl", const_cast<char*>(NS_XMPP_SASL));
    xhash_put(d->std_ns_prefixes, "conf", const_cast<char*>(NS_JABBERD_CONFIG_DIALBACK));
    xhash_put(d->std_ns_prefixes, "discoinfo", const_cast<char*>(NS_DISCO_INFO));
    xhash_put(d->std_ns_prefixes, "discoitems", const_cast<char*>(NS_DISCO_ITEMS));

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
    pool_cleanup(i->p, (pool_cleaner)xhash_free, d->hosts_xmpp);
    d->hosts_tls = xhash_new(max);
    pool_cleanup(i->p, (pool_cleaner)xhash_free, d->hosts_tls);
    d->hosts_auth = xhash_new(max);
    pool_cleanup(i->p, (pool_cleaner)xhash_free, d->hosts_auth);
    d->i = i;
    d->timeout_idle = j_atoi(xmlnode_get_list_item_data(xmlnode_get_tags(cfg, "conf:idletimeout", d->std_ns_prefixes), 0), 900);
    d->timeout_packets = j_atoi(xmlnode_get_list_item_data(xmlnode_get_tags(cfg, "conf:queuetimeout", d->std_ns_prefixes), 0), 30);
    d->timeout_auth = j_atoi(xmlnode_get_list_item_data(xmlnode_get_tags(cfg, "conf:authtimeout", d->std_ns_prefixes), 0), d->timeout_idle);
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
    register_beat(d->timeout_idle < 60 || d->timeout_auth < 60 ? (d->timeout_idle < d->timeout_auth ? d->timeout_idle : d->timeout_auth) : 60, dialback_beat_idle, (void *)d);
    register_beat(d->timeout_packets, dialback_out_beat_packets, (void *)d);

    xmlnode_free(cfg);
}
