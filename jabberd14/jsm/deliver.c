#include "jsm.h"


/* takes any packet and attempts to deliver it to the correct session/thread */
/* must have a valid to/from address already before getting here */
void js_deliver_local(jsmi si, jpacket p, HASHTABLE ht)
{
    udata user = NULL;
    session s = NULL;

    /* first, collect some facts */
    user = js_user(si, p->to, ht);
    s = js_session_get(user, p->to->resource);

    /* let some modules fight over it */
    if(js_mapi_call(si, e_DELIVER, p, user, s))
        return;

    if(p->to->user == NULL)
    { /* this is for the server */
        js_psend(si->mpserver,p);
        return;
    }

    if(s != NULL)
    { /* it's sent right to the resource */
        js_session_to(s, p);
        return;
    }

    if(user != NULL)
    { /* valid user, but no session */
        p->aux1 = (void *)user; /* performance hack, we already know the user */
        user->ref++; /* so it doesn't get cleaned up before the thread gets it */
        js_psend(si->mpoffline,p);
        return;
    }

    /* no user, so bounce the packet */
    js_bounce(si,p->x,TERROR_NOTFOUND);
}


result js_packet(instance i, dpacket p, void *arg)
{
    jsmi si = (jsmi)arg;
    jpacket jp;
    HASHTABLE ht;
    jid sto;
    session s;
    xmlnode x;

    jp = jpacket_new(p->x);

    log_debug(ZONE,"deliver(to[%s],from[%s],type[%d],packet[%s])",jid_full(jp->to),jid_full(jp->from),jp->type,xmlnode2str(jp->x));

    /* make sure this hostname is in the master table */
    if((ht = (HASHTABLE)ghash_get(si->hosts,jp->to->server)) == NULL)
    {
        /* XXX make USERS_PRIME configurable */
        ht = ghash_create(USERS_PRIME,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
        ghash_put(si->hosts,jp->to->server, (void *)ht);
    }

    /* if this is a session packet */
    if((sto = jid_new(p->p,xmlnode_get_attrib(p->x,"sto"))) != NULL)
    {
        if(sto->user == NULL && jp->type == JPACKET_IQ)
        {
            js_authreg(si, jp, ht);
            return r_DONE;
        }

        /* this is a packet to be processed as outgoing for this session */
        s = js_session_get(js_user(si, sto, ht),sto->resource);
        if(s != NULL)
        {
            js_session_from(s, jp);
        }else if(!(jpacket_subtype(jp) == JPACKET__ERROR && j_strcmp(xmlnode_get_attrib(xmlnode_get_tag(jp->x,"error"),"code"),"510") == 0)){ /* no session and not a 510 error */

            /* send an error msg to the client manager to make sure it knows there's no session */
            x = xmlnode_new_tag("message");
            xmlnode_put_attrib(x,"sto",xmlnode_get_attrib(jp->x,"sfrom"));
            jutil_error(x, TERROR_DISCONNECTED);
            deliver(dpacket_new(x), NULL);

            /* if this is a normal message store as offline */
            if(jp->type == JPACKET_MESSAGE)
            {
                xmlnode_put_attrib(jp->x,"to",jid_full(sto)); /* make sure the to="" is correct */
                jpacket_reset(jp);
                js_psend(si->mpoffline,jp);
            }else{
                log_notice(sto->server,"Dropping %s packet intended for session %s",xmlnode_get_name(jp->x),jid_full(sto));
                xmlnode_free(jp->x);
            }
        }
        return r_DONE;
    }

    /* normal server-server packet, should we make sure it's not spoofing us?  if so, if ghash_get(p->to->server) then bounce w/ security error */

    js_deliver_local(si, jp, ht);

    return r_DONE;
}


/* NOTE: any jpacket sent to deliver *MUST* match jpacket_new(p->x),
 * jpacket is simply a convenience wrapper
 */
void js_deliver(jsmi si, jpacket p)
{
    HASHTABLE ht;

    if(p->to == NULL)
    {
        log_warn(NULL,"jsm: Invalid Recipient, returning data %s",xmlnode2str(p->x));
        js_bounce(si,p->x,TERROR_BAD);
        return;
    }

    if(p->from == NULL)
    {
        log_warn(NULL,"jsm: Invalid Sender, discarding data %s",xmlnode2str(p->x));
        xmlnode_free(p->x);
        return;
    }

    log_debug(ZONE,"deliver(to[%s],from[%s],type[%d],packet[%s])",jid_full(p->to),jid_full(p->from),p->type,xmlnode2str(p->x));

    /* external to us */
    if((ht = (HASHTABLE)ghash_get(si->hosts,p->to->server)) != NULL)
    {
        js_deliver_local(si, p, ht);
        return;
    }
    deliver(dpacket_new(p->x), si->i);

}


void js_psend(pth_msgport_t mp, jpacket p)
{
    jpq q;

    if(p == NULL || mp == NULL)
        return;

    log_debug(ZONE,"psending to %X packet %X",mp,p);

    q = pmalloc(p->p, sizeof(_jpq));
    q->p = p;

    pth_msgport_put(mp, (pth_message_t *)q);
}


/* for fun, a tidbit from late nite irc (ya had to be there)
<temas> What is 1+1
<temas> Why did you hardcode stuff
<temas> Was the movie good?
<temas> DId the nukes explode?
*/
