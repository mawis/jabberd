#include "jsm.h"

/* NOTE: any jpacket sent to deliver *MUST* match jpacket_new(p->x),
 * jpacket is simply a convenience wrapper
 */
void js_deliver(jpacket p)
{
    udata user = NULL;
    static pth_msgport_t unknown_mp = NULL;
    static pth_msgport_t offline_mp = NULL;
    static pth_msgport_t server_mp = NULL;
    static mmaster ml = NULL;
    int flag_name = 0;
    session s = NULL;

    log_debug(ZONE,"deliver(to[%s],from[%s],type[%d],packet[%s])",jid_full(p->to),jid_full(p->from),p->type,xmlnode2str(p->x));

    if(unknown_mp == NULL)
        unknown_mp = pth_msgport_find("js_unknown");
    if(offline_mp == NULL)
        offline_mp = pth_msgport_find("js_offline");
    if(server_mp == NULL)
        server_mp = pth_msgport_find("js_server");
    if(ml == NULL)
        ml = js_mapi_master(P_DELIVER);

    /* important main function, takes any packet and attempts to deliver it to the correct session/thread */

    if(p->to == NULL)
    {
        log_warn("jsm","Invalid Recipient, returning data %s",xmlnode2str(p->x));
        js_bounce(p->x,TERROR_BAD);
        return;
    }

    if(p->from == NULL)
    {
        log_warn("jsm","Invalid Sender, discarding data %s",xmlnode2str(p->x));
        xmlnode_free(p->x);
        return;
    }

    /* first, collect some facts */
    flag_name = js_config_name(C_CHECK,p->to->server);
    if(flag_name)
    {
        user = js_user(p->to->user);
        s = js_session_get(user, p->to->resource);
    }

    /* let some modules fight over it */
    if(js_mapi_call(P_DELIVER, ml->l, p, user, s, flag_name))
        return;

    if(flag_name && p->to->user == NULL)
    { /* this is for the server jabber:server.host */
        js_psend(server_mp,p);
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
        js_psend(offline_mp,p);
        return;
    }

    /* everything else hit's the bit bucket */
    js_psend(unknown_mp,p);
}

void js_psend(pth_msgport_t mp, jpacket p)
{
    static pth_msgport_t unknown_mp = NULL;
    jpq q;

    if(p == NULL || mp == NULL)
        return;

    log_debug(ZONE,"psending to %X packet %X",mp,p);

    if(unknown_mp == NULL)
        unknown_mp = pth_msgport_find("js_unknown");

    q = pmalloc(p->p, sizeof(_jpq));
    q->p = p;

    q->head.m_replyport = unknown_mp;
    pth_msgport_put(mp, (pth_message_t *)q);
}


/* for fun, a tidbit from late nite irc (ya had to be there)
<temas> What is 1+1
<temas> Why did you hardcode stuff
<temas> Was the movie good?
<temas> DId the nukes explode?
*/
