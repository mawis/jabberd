#include "jsm.h"

mreturn mod_auth_plain(mapi m, void *arg)
{
    char *passA, *passB;
    xmlnode xdb;

    log_debug("mod_auth_plain","checking");

    if((passA = xmlnode_get_tag_data(m->packet->iq, "password")) == NULL)
        return M_PASS;

    /* make sure we can get the auth packet and that it contains a password */
    xdb = xdb_get(m->si->xc, m->user->id->server, m->user->id, NS_AUTH);
    if(xdb == NULL || (passB = xmlnode_get_data(xdb_get(m->si->xc, m->user->id->server, m->user->id, NS_AUTH))) == NULL)
    {
        xmlnode_free(xdb);
        return M_PASS;
    }

    log_debug("mod_auth_plain","comparing %s %s",passA,passB);

    if(strcmp(passA, passB) != 0)
        jutil_error(m->packet->x, TERROR_AUTH);
    else
        jutil_iqresult(m->packet->x);

    xmlnode_free(xdb); /* free xdb results */

    return M_HANDLED;
}

void mod_auth(jsmi si)
{
    log_debug("mod_auth","init");
    js_mapi_register(si,e_AUTH, mod_auth_plain, NULL);
}
