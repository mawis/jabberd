#include "jserver.h"

mreturn mod_time_reply(mapi m, void *arg)
{
    time_t t;
    char *tstr;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(!NSCHECK(m->packet->iq,NS_TIME)) return M_PASS;

    /* first, is this a valid request? */
    if(jpacket_subtype(m->packet) != JPACKET__GET)
    {
        js_bounce(m->packet->x,TERROR_NOTALLOWED);
        return M_HANDLED;
    }

    log_debug("mod_time","handling time query from %s",jid_full(m->packet->from));

    jutil_iqresult(m->packet->x);
    xmlnode_put_attrib(xmlnode_insert_tag(m->packet->x,"query"),"xmlns",NS_TIME);
    jpacket_reset(m->packet);
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"utc"),jutil_timestamp(),-1);
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"tz"),tzname[0],-1);

    /* create nice display time */
    t = time(NULL);
    tstr = ctime(&t);
    tstr[strlen(tstr) - 1] = '\0'; /* cut off newline */
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"display"),tstr,-1);

    js_deliver(m->packet);

    return M_HANDLED;
}

void mod_time(void)
{
    js_mapi_register(P_SERVER,mod_time_reply,NULL);
}


