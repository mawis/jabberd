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

/*
    <!-- For use without an external DNS component -->
  <service id="127.0.0.1 s2s">
    <host/>
    <load main="pthsock_server">
      <pthsock_server>../load/pthsock_server.so</pthsock_server>
    </load>
  </service>

  <!-- for use with an external DNS component -->
  <service id="127.0.0.1 s2s">
    <host>pthsock-s2s.127.0.0.1</host> <!-- add this host to DNS config section -->
    <load main="pthsock_server">
      <pthsock_server>../load/pthsock_server.so</pthsock_server>
    </load>
  </service>

DIALBACK: 

A->B
    A: <db:result to=B from=A>...</db:result>

    B->A
        B: <db:verify to=A from=B id=asdf>...</db:verify>
        A: <db:verify type="valid" to=B from=A id=asdf/>

A->B
    B: <db:result type="valid" to=A from=B/>
*/

#include "dialback.h"

/* we need a decently random string in a few places */
char *dialback_randstr(void)
{
    static char ret[41];

    sprintf(ret,"%d",rand());
    shahash_r(ret,ret);
    return ret;
}

/* convenience */
char *dialback_merlin(pool p, char *secret, char *to, char *challenge)
{
    static char res[41];

    shahash_r(secret,                       res);
    shahash_r(spools(p, res, to, p),        res);
    shahash_r(spools(p, res, challenge, p), res);

    return res;
}

void dialback_miod_write(miod md, xmlnode x)
{
    md->count++;
    md->last = time(NULL);
    mio_write(md->m, x, NULL, -1);
}

miod dialback_miod_new(db d, mio m)
{
    miod md;

    md = pmalloco(m->p, sizeof(_miod));
    md->m = m;
    md->d = d;
    md->last = time(NULL);

    return md;
}

/******* little wrapper to keep our hash tables in check ****/
struct miodc
{
    miod md;
    HASHTABLE ht;
    jid key;
};
/* clean up a hashtable entry containing this miod */
void _dialback_miod_hash_cleanup(void *arg)
{
    struct miodc *mdc = (struct miodc *)arg;
    if(ghash_get(mdc->ht,jid_full(mdc->key)) == mdc->md)
        ghash_remove(mdc->ht,jid_full(mdc->key));

    /* cool place for logging, eh? interesting way of detecting things too, *g* */
    if(mdc->ht == mdc->md->d->out_ok_db){
        log_record(mdc->key->server, "out", "dialback", "%d %s %s", mdc->md->count, mdc->md->m->ip, mdc->key->resource);
    }else if(mdc->ht == mdc->md->d->out_ok_legacy){
        log_record(mdc->key->server, "out", "legacy", "%d %s %s", mdc->md->count, mdc->md->m->ip, mdc->key->resource);
    }else if(mdc->ht == mdc->md->d->in_ok_db){
        log_record(mdc->key->server, "in", "dialback", "%d %s %s", mdc->md->count, mdc->md->m->ip, mdc->key->resource);
    }else if(mdc->ht == mdc->md->d->in_ok_legacy){
        log_record(mdc->key->server, "in", "legacy", "%d %s %s", mdc->md->count, mdc->md->m->ip, mdc->key->resource);
    }
}
void dialback_miod_hash(miod md, HASHTABLE ht, jid key)
{
    struct miodc *mdc;
    mdc = pmalloco(md->m->p,sizeof(struct miodc));
    mdc->md = md;
    mdc->ht = ht;
    mdc->key = jid_new(md->m->p,jid_full(key));
    pool_cleanup(md->m->p, _dialback_miod_hash_cleanup, (void *)mdc);
    ghash_put(ht, jid_full(mdc->key), md);
}


/* phandler callback, send packets to another server */
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
    if(j_strcmp(dp->host,d->i->id) == 0)
    {
        xmlnode_put_attrib(x,"to",xmlnode_get_attrib(x,"ofrom"));
        xmlnode_hide_attrib(x,"ofrom"); /* repair the addresses */
        dialback_in_verify(d, x);
        return r_DONE;
    }

    dialback_out_packet(d, x, ip);
    return r_DONE;
}


/* callback for walking each miod-value host hash tree */
int _dialback_beat_idle(void *arg, const void *key, void *data)
{
    miod md = (miod)data;
    if(((int)arg - md->last) >= md->d->timeout_idle)
    {
        mio_write(md->m, NULL, "<stream:error>Idle Timeout</stream:error>", -1);
        mio_close(md->m);
    }
    return 1;
}

/* heartbeat checker for timed out idle hosts */
result dialback_beat_idle(void *arg)
{
    db d = (db)arg;
    ghash_walk(d->out_ok_db,_dialback_beat_idle,(void*)time(NULL));
    ghash_walk(d->out_ok_legacy,_dialback_beat_idle,(void*)time(NULL));
    ghash_walk(d->in_ok_db,_dialback_beat_idle,(void*)time(NULL));
    ghash_walk(d->in_ok_legacy,_dialback_beat_idle,(void*)time(NULL));
    return r_DONE;
}

/*** everything starts here ***/
void dialback(instance i, xmlnode x)
{
    db d;
    xmlnode cfg, cur;
    struct karma k;
    int max;

    log_debug(ZONE,"dialback loading");
    srand(time(NULL));

    /* get the config */
    cfg = xdb_get(xdb_cache(i),jid_new(xmlnode_pool(x),"config@-internal"),"jabber:config:dialback");

    max = j_atoi(xmlnode_get_tag_data(cfg,"maxhosts"),997);
    d = pmalloco(i->p,sizeof(_db));
    d->out_connecting = ghash_create(67,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
    d->out_ok_db = ghash_create(max,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
    d->out_ok_legacy = ghash_create(max,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
    d->in_id = ghash_create(max,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
    d->in_ok_db = ghash_create(max,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
    d->in_ok_legacy = ghash_create(max,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
    d->i = i;
    d->timeout_idle = j_atoi(xmlnode_get_tag_data(cfg,"idletimeout"),600);
    d->timeout_packets = j_atoi(xmlnode_get_tag_data(cfg,"queuetimeout"),30);
    d->secret = xmlnode_get_attrib(cfg,"secret");
    if(d->secret == NULL) /* if there's no configured secret, make one on the fly */
        d->secret = pstrdup(i->p,dialback_randstr());
    if(xmlnode_get_tag(cfg,"legacy") != NULL)
        d->legacy = 1;


    k.val=KARMA_INIT;
    k.bytes=0;
    cur = xmlnode_get_tag(cfg,"karma");
    k.max=j_atoi(xmlnode_get_tag_data(cur,"max"),KARMA_MAX);
    k.inc=j_atoi(xmlnode_get_tag_data(cur,"inc"),KARMA_INC);
    k.dec=j_atoi(xmlnode_get_tag_data(cur,"dec"),KARMA_DEC);
    k.restore=j_atoi(xmlnode_get_tag_data(cur,"restore"),KARMA_RESTORE);
    k.penalty=j_atoi(xmlnode_get_data(cur),KARMA_PENALTY);

    if((cur = xmlnode_get_tag(cfg,"ip")) != NULL)
        for(;cur != NULL; xmlnode_hide(cur), cur = xmlnode_get_tag(cfg,"ip"))
        {
            mio m;
            m = mio_listen(j_atoi(xmlnode_get_attrib(cur,"port"),5269),xmlnode_get_data(cur),dialback_in_read,(void*)d, MIO_LISTEN_XML);
            mio_rate(m, j_atoi(xmlnode_get_attrib(xmlnode_get_tag(cfg,"rate"),"time"),5),j_atoi(xmlnode_get_attrib(xmlnode_get_tag(cfg,"rate"),"points"),25));
            mio_karma2(m, &k);
        }
    else /* no special config, use defaults */
    {
        mio m;
        m = mio_listen(5269,NULL,dialback_in_read,(void*)d, MIO_LISTEN_XML);
        mio_rate(m, j_atoi(xmlnode_get_attrib(xmlnode_get_tag(cfg,"rate"),"time"),5), j_atoi(xmlnode_get_attrib(xmlnode_get_tag(cfg,"rate"),"points"),25));
        mio_karma2(m, &k);
    }

    register_phandler(i,o_DELIVER,dialback_packets,(void*)d);
    register_beat(d->timeout_idle, dialback_beat_idle, (void *)d);
    register_beat(d->timeout_packets, dialback_out_beat_packets, (void *)d);

    xmlnode_free(cfg);
}
