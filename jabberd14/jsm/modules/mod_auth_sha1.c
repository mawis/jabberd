#include <jserver.h>

mreturn mod_auth_digest(mapi m, void *arg)
{
    spool s;
    char *sid;
    char *digest;
    char *passxdb;
    char *mydigest;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(m->variant != MAPI_VARAUTH) return M_PASS;

    log_debug("mod_auth_sha1","checking");

    passxdb = xmlnode_get_data(js_xdb_get(m->user, NS_AUTH));
    digest = xmlnode_get_tag_data(m->packet->iq, "digest");
    sid = xmlnode_get_attrib(m->packet->x, "sid");

    /* Concat the stream id and password */
    /* SHA it up */
    log_debug("mod_auth_sha1", "Got SID: %s", sid);
    s = spool_new(m->packet->p);
    spooler(s,sid,passxdb,s);

    mydigest = shahash(spool_print(s));

    log_debug("mod_auth_sha1","comparing %s %s",digest,mydigest);

    if(digest == NULL || sid == NULL || mydigest == NULL) return M_PASS;

    if(strcmp(digest, mydigest) != 0)
        jutil_error(m->packet->x, TERROR_AUTH);
    else
        jutil_iqresult(m->packet->x);

    return M_HANDLED;
}

void mod_auth_sha1(void)
{
    log_debug("mod_auth_sha1","init");
    js_mapi_register(P_OFFLINE, mod_auth_digest, NULL);
}
