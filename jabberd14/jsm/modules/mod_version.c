#include "jsm.h"
#include <sys/utsname.h>

mreturn mod_version_reply(mapi m, void *arg)
{
    struct utsname un;
    xmlnode os;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(!NSCHECK(m->packet->iq,NS_VERSION)) return M_PASS;

    /* first, is this a valid request? */
    if(jpacket_subtype(m->packet) != JPACKET__GET)
    {
        js_bounce(m->si,m->packet->x,TERROR_NOTALLOWED);
        return M_HANDLED;
    }

    log_debug("mod_version","handling query from",jid_full(m->packet->from));

    jutil_iqresult(m->packet->x);
    xmlnode_put_attrib(xmlnode_insert_tag(m->packet->x,"query"),"xmlns",NS_VERSION);
    jpacket_reset(m->packet);
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"name"),PACKAGE,-1);
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"ver"),VERSION,-1);

    uname(&un);
    os = xmlnode_insert_tag(m->packet->iq,"os");
    xmlnode_insert_cdata(os,un.sysname,-1);
    xmlnode_insert_cdata(os," ",1);
    xmlnode_insert_cdata(os,un.release,-1);

    js_deliver(m->si,m->packet);

    return M_HANDLED;
}

void mod_version(jsmi si)
{
    js_mapi_register(si,e_SERVER,mod_version_reply,NULL);
}


