#include "jserver.h"

mreturn mod_echo_reply(mapi m, void *arg)
{
    if(m->packet->type != JPACKET_MESSAGE) return M_IGNORE;

    /* first, is this a valid request? */
    if(m->packet->to->resource == NULL || strncasecmp(m->packet->to->resource,"echo",4) != 0) return M_PASS;

    log_debug("mod_echo","handling echo request from %s",jid_full(m->packet->from));

    xmlnode_put_attrib(m->packet->x,"from",jid_full(m->packet->to));
    xmlnode_put_attrib(m->packet->x,"to",jid_full(m->packet->from));
    jpacket_reset(m->packet);
    js_deliver(m->packet);

    return M_HANDLED;
}

void mod_echo(void)
{
    js_mapi_register(P_SERVER,mod_echo_reply,NULL);
}


