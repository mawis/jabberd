#include <jsm.h>

mreturn mod_auth_digest(mapi m, void *arg)
{
    spool s;
    char *sid;
    char *digest;
    char *passxdb;
    char *mydigest;
    xmlnode xdb;

    log_debug("mod_auth_sha1","checking");

    xdb = xdb_get(m->si->xc, m->user->id->server, m->user->id, NS_AUTH);
    passxdb = xmlnode_get_data(xdb);
    digest = xmlnode_get_tag_data(m->packet->iq, "digest");
    sid = xmlnode_get_attrib(xmlnode_get_tag(m->packet->iq,"digest"), "sid");

    /* Concat the stream id and password */
    /* SHA it up */
    log_debug("mod_auth_sha1", "Got SID: %s", sid);
    s = spool_new(m->packet->p);
    spooler(s,sid,passxdb,s);

    mydigest = shahash(spool_print(s));

    /* don't need the xdb data anymore */
    xmlnode_free(xdb);

    log_debug("mod_auth_sha1","comparing %s %s",digest,mydigest);

    if(digest == NULL || sid == NULL || mydigest == NULL) return M_PASS;

    if(strcmp(digest, mydigest) != 0)
        jutil_error(m->packet->x, TERROR_AUTH);
    else
        jutil_iqresult(m->packet->x);

    return M_HANDLED;
}

void mod_auth_sha1(jsmi si)
{
    log_debug("mod_auth_sha1","init");
    js_mapi_register(si,e_AUTH, mod_auth_digest, NULL);
}
