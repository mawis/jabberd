#include "jsm.h"

mreturn mod_auth_plain(mapi m, void *arg)
{
    char *passA, *passB;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(m->variant != MAPI_VARAUTH) return M_PASS;

    log_debug("mod_auth_plain","checking");

    passA = xmlnode_get_tag_data(m->packet->iq, "password");
    passB = xmlnode_get_data(js_xdb_get(m->user, NS_AUTH));

    log_debug("mod_auth_plain","comparing %s %s",passA,passB);

    if(passA == NULL || passB == NULL) return M_PASS;

    if(strcmp(passA, passB) != 0)
        jutil_error(m->packet->x, TERROR_AUTH);
    else
        jutil_iqresult(m->packet->x);

    return M_HANDLED;
}

void mod_auth(jsmi i)
{
    log_debug("mod_auth","init");
    js_mapi_register(P_OFFLINE, mod_auth_plain, NULL);
}
