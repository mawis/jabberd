#include "jserver.h"

mreturn mod_register_offline(mapi m, void *arg)
{
    char *user;
    xmlnode q, reg;
    udata u;
    pool p;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;

    if(m->variant != MAPI_VARREGISTER) return M_PASS;

    if((reg = js_config("register")) == NULL) return M_PASS;

    log_debug("mod_register","checking");

    switch(jpacket_subtype(m->packet))
    {
    case JPACKET__GET:
        /* create reply to the get */
        jutil_iqresult(m->packet->x);

        /* create a new query */
        q = xmlnode_insert_tag(m->packet->x, "query");
        xmlnode_put_attrib(q,"xmlns",NS_REGISTER);

        /* copy in the registration fields from the config file */
        xmlnode_insert_node(q,xmlnode_get_firstchild(reg));

        /* insert the key, we don't need to check it, but we'll send it :) */
        xmlnode_insert_cdata(xmlnode_insert_tag(q,"key"),jutil_regkey(NULL,"foobar"),-1);
        break;

    case JPACKET__SET:
        /* make sure they sent a username */
        user = xmlnode_get_tag_data(m->packet->iq,"username");
        if(user == NULL)
        {
            jutil_error(m->packet->x, TERROR_NOTACCEPTABLE);
            break;
        }

        /* make sure the username they want isn't in use */
        u = js_user(user);
        if(u != NULL)
        {
            jutil_error(m->packet->x, (terror){409,"Username Not Available"});
            break;
        }

        log_debug(ZONE,"processing valid registration for %s",user);

        /* HACK: create a temporary udata struct so we can tell xdb to save the data somewhere */
        p = pool_new();
        u = pmalloc(p, sizeof(_udata));
        memset(u, '\0', sizeof(_udata));
        u->p = p;
        u->user = pstrdup(p, user);

        /* save the registration data */
        q = xmlnode_dup_pool(p,m->packet->iq); /* HACK: put the data packet in the same pool :) */
        xmlnode_hide(xmlnode_get_tag(q,"password")); /* hide the username/password from the reg db */
        xmlnode_hide(xmlnode_get_tag(q,"username"));
        js_xdb_set(u, NS_REGISTER, q);

        /* save the auth data */
        js_xdb_set(u, NS_AUTH, xmlnode_get_tag(m->packet->iq,"password"));

        /* clean up and respond */
        pool_free(p);
        jutil_iqresult(m->packet->x);
        break;

    default:
        return M_PASS;
    }

    return M_HANDLED;
}

mreturn mod_register_server(mapi m, void *arg)
{
    xmlnode q, reg, cur, check;
    udata u;

    /* pre-requisites */
    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(!NSCHECK(m->packet->iq,NS_REGISTER)) return M_PASS;
    if(m->packet->from->user == NULL || !js_config_name(C_CHECK, m->packet->from->server)) return M_PASS;
    if(js_config("register") == NULL) return M_PASS;

    log_debug("mod_register","updating");

    /* get the sender */
    u = js_user(m->packet->from->user);
    if(u == NULL)
    {
        js_bounce(m->packet->x,TERROR_FORBIDDEN);
        return M_HANDLED;
    }

    /* check for their registration */
    reg = js_xdb_get(u,NS_REGISTER);
    if(reg == NULL)
    {
        js_bounce(m->packet->x,TERROR_REGISTER);
        return M_HANDLED;
    }

    switch(jpacket_subtype(m->packet))
    {
    case JPACKET__GET:
        /* create reply to the get */
        jutil_iqresult(m->packet->x);

        /* create a new query */
        q = xmlnode_insert_tag(m->packet->x, "query");
        xmlnode_put_attrib(q,"xmlns",NS_REGISTER);

        /* copy in the registration fields from the config file */
        xmlnode_insert_node(q,xmlnode_get_firstchild(js_config("register")));

        /* insert the key, we don't need to check it, but we'll send it :) */
        xmlnode_insert_cdata(xmlnode_insert_tag(q,"key"),jutil_regkey(NULL,"foobar"),-1);

        /* replace fields with already-registered ones */
        for(cur = xmlnode_get_firstchild(q); cur != NULL; cur = xmlnode_get_nextsibling(cur))
        {
            if(xmlnode_get_type(cur) != NTYPE_TAG) continue;

            check = xmlnode_get_tag(reg,xmlnode_get_name(cur));
            if(check == NULL) continue;

            xmlnode_insert_node(cur,xmlnode_get_firstchild(check));
        }

        /* add the registered flag and hide the username flag */
        xmlnode_insert_tag(q,"registered");
        xmlnode_hide(xmlnode_get_tag(q,"username"));

        break;

    case JPACKET__SET:
        if(xmlnode_get_tag(m->packet->iq,"remove") != NULL)
        {
            log_debug(ZONE,"REMOVING registration for %s",u->user);

            /* remove the registration and auth and any misc data */
            js_xdb_set(u, NS_REGISTER, NULL);
            js_xdb_set(u, NS_AUTH, NULL);
            js_xdb_set(u, NS_PRIVATE, NULL);
            js_xdb_set(u, NS_ROSTER, NULL);
            js_xdb_set(u, NS_VCARD, NULL);
        }else{
            log_debug(ZONE,"updating registration for %s",u->user);

            /* update the registration data */
            q = xmlnode_dup(m->packet->iq);
            xmlnode_hide(xmlnode_get_tag(q,"username")); /* hide the username/password from the reg db */
            xmlnode_hide(xmlnode_get_tag(q,"password"));
            js_xdb_set(u, NS_REGISTER, q);

            /* reset the password */
            if(xmlnode_get_tag_data(m->packet->iq,"password") != NULL)
                js_xdb_set(u, NS_AUTH, xmlnode_dup(xmlnode_get_tag(m->packet->iq,"password")));
        }
        /* clean up and respond */
        jutil_iqresult(m->packet->x);
        break;

    default:
        return M_PASS;
    }

    js_deliver(jpacket_reset(m->packet));
    return M_HANDLED;
}

void mod_register()
{
    log_debug("mod_register","init");
    js_mapi_register(P_OFFLINE, mod_register_offline, NULL);
    js_mapi_register(P_SERVER, mod_register_server, NULL);
}
