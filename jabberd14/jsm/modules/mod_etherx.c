#include "jserver.h"

void mod_etherx_receive(epacket e);

/* this is a special internal ehandler manager, one ehandle per server name */
ehandler mod_etherx_handlers(command cmd, char *name)
{
    static ehandler names = NULL, get = NULL;
    ehandler eh;
    xmlnode cur;

    switch(cmd)
    {
    case C_SET: /* only intended to be run at config/startup time */
        if(mod_etherx_handlers(C_CHECK,name) != NULL || name == NULL)
            return NULL;
        eh = ehandler_new(mod_etherx_receive,name,NS_SERVER);
        eh->next = names;
        names = eh;
        return eh;
        break;
    case C_CHECK:
        eh = names;
        while(eh != NULL)
        {
            if(j_strcmp(name,eh->host) == 0)
                return eh;
            eh = eh->next;
        }
        break;
    case C_GET: /* loops through name list, returns NULL at end */
        if(get == NULL)
            get = names;
        else
            get = get->next;
        if(get != NULL)
            return get;
        break;
    case C_INIT:
        for(cur = xmlnode_get_firstchild(js_config("names")); cur != NULL; cur = xmlnode_get_nextsibling(cur))
            if(xmlnode_get_type(cur) == NTYPE_TAG)
                mod_etherx_handlers(C_SET,xmlnode_get_data(cur));
        break;
    default:
    }
    return NULL;
}

void mod_etherx_receive(epacket e)
{
    ehandler eh;
    jpacket p;

    /* handles incoming packets from etherx, we get to free the mem */
    switch(e->type)
    {
    case EPACKET_NORMAL:
        log_debug(ZONE,"EXTERNAL: got epacket from[%s]: %s",e->from, xmlnode2str(e->x));
        p = jpacket_new(e->x);

        /* if it's not a good packet, or claiming to be from us, bounce it */
        if(p->type == JPACKET_UNKNOWN  || p->to == NULL || p->from == NULL || mod_etherx_handlers(C_CHECK,p->from->server) != NULL)
        {
            if(jpacket_subtype(p) == JPACKET__ERROR)
            { /* you can't bounce an error! */
                log_error("mod_etherx","Discarding invalid data %s",xmlnode2str(p->x));
                xmlnode_free(p->x);
                return;
            }
            jutil_error(p->x,TERROR_BAD);
            eh = mod_etherx_handlers(C_CHECK,e->to);
            ehandler_send(eh,p->x,e->from);
            return;
        }

        js_deliver(jpacket_new(e->x));
        return;
    case EPACKET_ERROR:
        log_debug(ZONE,"EXTERNAL: got error epacket bounce to %s reason %s",e->from,e->error);
        js_bounce(e->x,TERROR_EXTERNAL);
        return;
    }
    xmlnode_free(e->x);
}

mreturn mod_etherx_external(mapi m, void *arg)
{
    ehandler eh;

    if(!m->variant)
    { /* the server name is external */
        log_debug(ZONE,"delivering external packets");

        eh = mod_etherx_handlers(C_CHECK,m->packet->from->server);
        if(eh == NULL) return M_PASS; /* shouldn't happen */
        ehandler_send(eh,m->packet->x,m->packet->to->server); /* will consume/free x */
        return M_HANDLED;
    }

    return M_PASS;
}

void mod_etherx_config(void)
{
    char *secret, *host;

    secret = xmlnode_get_data(js_config("etherx/secret"));
    host = xmlnode_get_data(js_config("etherx/remote"));

    if(secret != NULL)
        etherx_init(secret,host);
    else
        etherx_init("test",host);
}

void mod_etherx(void)
{
    log_debug("mod_etherx","init");

    if(js_config("etherx") == NULL)
    {
        log_warn("mod_etherx","No etherx section found in config, disabling external traffic");
        return;
    }

    mod_etherx_config();

    mod_etherx_handlers(C_INIT,NULL);
    js_mapi_register(P_DELIVER, mod_etherx_external, NULL);
}
