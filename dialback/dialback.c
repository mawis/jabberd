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
 * identity verification using dialback, SASL and STARTTLS is not supported.
 *
 * By adding a <legacy/> element to the dialback configuration you can also enable
 * the old stone-age server to server protocol which shouldn't be needed anymore.
 * The stone-age protocol as no protection against identity spoofing.
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
 * generate a random string (not thead-safe)
 *
 * This function generates a random ASCII string.
 *
 * @returns pointer to a string with 40 characters of random data
 */
char *dialback_randstr(void)
{
    static char ret[41];

    sprintf(ret,"%d",rand());
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
        log_warn(md->d->i->id, "dropping invalid packet from server: %s",xmlnode2str(x));
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
        log_record(mdc->key->server, "out", "dialback", "%d %s %s", mdc->md->count, mdc->md->m->ip, mdc->key->resource);
    }else if(mdc->ht == mdc->md->d->out_ok_legacy){
        unregister_instance(mdc->md->d->i, mdc->key->server);
        log_record(mdc->key->server, "out", "legacy", "%d %s %s", mdc->md->count, mdc->md->m->ip, mdc->key->resource);
    }else if(mdc->ht == mdc->md->d->in_ok_db){
        log_record(mdc->key->server, "in", "dialback", "%d %s %s", mdc->md->count, mdc->md->m->ip, mdc->key->resource);
    }else if(mdc->ht == mdc->md->d->in_ok_legacy){
        log_record(mdc->key->server, "in", "legacy", "%d %s %s", mdc->md->count, mdc->md->m->ip, mdc->key->resource);
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
    if(ht == md->d->out_ok_db || ht == md->d->out_ok_legacy)
    {
        dialback_ip_set(md->d, key, md->m->ip); /* save the ip since it won't be going through the dnsrv anymore */
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

    ret =  pstrdup(host->p,xmlnode_get_attrib((xmlnode)xhash_get(d->nscache,host->server),"i"));
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
    cache = xmlnode_new_tag("d");
    xmlnode_put_attrib(cache,"h",host->server);
    xmlnode_put_attrib(cache,"i",ip);
    xhash_put(d->nscache,xmlnode_get_attrib(cache,"h"),(void*)cache);
    log_debug2(ZONE, LOGT_IO, "cached ip %s for %s",ip,host->server);

    /* free any old entry that's been replaced */
    xmlnode_free(old);
}

/**
 * phandler callback, send packets to another server
 *
 * @param i the dialback instance we are running in
 * @param dp the dialback packet
 * @param arg pointer to the db structure with the context of the dialback component instance
 * @return always r_DONE
 */
result dialback_packets(instance i, dpacket dp, void *arg)
{
    db d = (db)arg;
    xmlnode x = dp->x;
    char *ip = NULL;

    /* routes are from dnsrv w/ the needed ip */
    if(dp->type == p_ROUTE)
    {
        x = xmlnode_get_firstchild(x);
        ip = xmlnode_get_attrib(dp->x,"ip");
    }

    /* all packets going to our "id" go to the incoming handler, 
     * it uses that id to send out db:verifies to other servers, 
     * and end up here when they bounce */
    if(j_strcmp(xmlnode_get_attrib(x,"to"),d->i->id) == 0)
    {
        xmlnode_put_attrib(x,"to",xmlnode_get_attrib(x,"ofrom"));
        xmlnode_hide_attrib(x,"ofrom"); /* repair the addresses */
        dialback_in_verify(d, x);
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
    if(((int)*(time_t*)arg - md->last) >= md->d->timeout_idle)
    {
        log_debug2(ZONE, LOGT_IO, "Idle Timeout on socket %d to %s",md->m->fd, md->m->ip);
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
    xhash_walk(d->out_ok_legacy,_dialback_beat_idle,(void*)&ttmp);
    xhash_walk(d->in_ok_db,_dialback_beat_idle,(void*)&ttmp);
    xhash_walk(d->in_ok_legacy,_dialback_beat_idle,(void*)&ttmp);
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
    struct karma k;
    int max;
    int rate_time, rate_points;
    int set_rate = 0, set_karma=0;

    log_debug2(ZONE, LOGT_INIT, "dialback loading");
    srand(time(NULL));

    /* get the config */
    cfg = xdb_get(xdb_cache(i),jid_new(xmlnode_pool(x),"config@-internal"),"jabber:config:dialback");

    max = j_atoi(xmlnode_get_tag_data(cfg,"maxhosts"),997);
    d = pmalloco(i->p,sizeof(_db));
    d->nscache = xhash_new(max);
    pool_cleanup(i->p, (pool_cleaner)xhash_free, d->nscache);
    d->out_connecting = xhash_new(67);
    pool_cleanup(i->p, (pool_cleaner)xhash_free, d->out_connecting);
    d->out_ok_db = xhash_new(max);
    pool_cleanup(i->p, (pool_cleaner)xhash_free, d->out_ok_db);
    d->out_ok_legacy = xhash_new(max);
    pool_cleanup(i->p, (pool_cleaner)xhash_free, d->out_ok_legacy);
    d->in_id = xhash_new(max);
    pool_cleanup(i->p, (pool_cleaner)xhash_free, d->in_id);
    d->in_ok_db = xhash_new(max);
    pool_cleanup(i->p, (pool_cleaner)xhash_free, d->in_ok_db);
    d->in_ok_legacy = xhash_new(max);
    pool_cleanup(i->p, (pool_cleaner)xhash_free, d->in_ok_legacy);
    d->i = i;
    d->timeout_idle = j_atoi(xmlnode_get_tag_data(cfg,"idletimeout"),900);
    d->timeout_packets = j_atoi(xmlnode_get_tag_data(cfg,"queuetimeout"),30);
    d->secret = pstrdup(i->p,xmlnode_get_tag_data(cfg,"secret"));
    if(d->secret == NULL) /* if there's no configured secret, make one on the fly */
        d->secret = pstrdup(i->p,dialback_randstr());
    if(xmlnode_get_tag(cfg,"legacy") != NULL)
        d->legacy = 1;

    /* Get rate info if it exists */
    if((cur = xmlnode_get_tag(cfg, "rate")) != NULL)
    {
        rate_time   = j_atoi(xmlnode_get_attrib(cur, "time"), 0);
        rate_points = j_atoi(xmlnode_get_attrib(cur, "points"), 0);
        set_rate = 1; /* set to true */
    }

    /* Get karma info if it exists */
    if((cur = xmlnode_get_tag(cfg, "karma")) != NULL)
    {
         k.val         = j_atoi(xmlnode_get_tag_data(cur, "init"), KARMA_INIT);
         k.max         = j_atoi(xmlnode_get_tag_data(cur, "max"), KARMA_MAX);
         k.inc         = j_atoi(xmlnode_get_tag_data(cur, "inc"), KARMA_INC);
         k.dec         = j_atoi(xmlnode_get_tag_data(cur, "dec"), KARMA_DEC);
         k.restore     = j_atoi(xmlnode_get_tag_data(cur, "restore"), KARMA_RESTORE);
         k.penalty     = j_atoi(xmlnode_get_tag_data(cur, "penalty"), KARMA_PENALTY);
         k.reset_meter = j_atoi(xmlnode_get_tag_data(cur, "resetmeter"), KARMA_RESETMETER);
         set_karma = 1; /* set to true */
    }

    if((cur = xmlnode_get_tag(cfg,"ip")) != NULL)
        for(;cur != NULL; xmlnode_hide(cur), cur = xmlnode_get_tag(cfg,"ip"))
        {
            mio m;
            m = mio_listen(j_atoi(xmlnode_get_attrib(cur,"port"),5269),xmlnode_get_data(cur),dialback_in_read,(void*)d, MIO_LISTEN_XML);
            if(m == NULL)
                return;
            /* Set New rate and points */
            if(set_rate == 1) mio_rate(m, rate_time, rate_points);
            /* Set New karma values */
            if(set_karma == 1) mio_karma2(m, &k);
        }
    else /* no special config, use defaults */
    {
        mio m;
        m = mio_listen(5269,NULL,dialback_in_read,(void*)d, MIO_LISTEN_XML);
        if(m == NULL) return;
        /* Set New rate and points */
        if(set_rate == 1) mio_rate(m, rate_time, rate_points);
        /* Set New karma values */
        if(set_karma == 1) mio_karma2(m, &k);
    }

    register_phandler(i,o_DELIVER,dialback_packets,(void*)d);
    register_beat(d->timeout_idle, dialback_beat_idle, (void *)d);
    register_beat(d->timeout_packets, dialback_out_beat_packets, (void *)d);

    xmlnode_free(cfg);
}
