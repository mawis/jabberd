#include "jserver.h"
#define MAX_SERVERS 500

int farm_size=0;
char **servers=NULL;
pool p=NULL;

int get_server(int max,char *user)
{
    int t;
    char *hash;
    int hash_len;

    if(max==0||user==NULL) return -1;
    hash=shahash(user);
    hash_len=strlen(hash);

    t=(int)hash[0]+hash[hash_len];
    return (int)(t%max);
}

mreturn mod_farm_deliver(mapi m, void *arg)
{
    int s_index=0;
    if(m->variant==0) return M_PASS;
    /* if this is an auth packet, send back a 302 to the right server */
    if(NSCHECK(m->packet->iq,NS_AUTH))
    {
        s_index=get_server(farm_size,xmlnode_get_tag_data(m->packet->iq,"username"));
        if(!js_config_name(C_CHECK,servers[s_index]))
        {
            /* return 302 error */
            xmlnode error;
            jutil_tofrom(m->packet->x);
            error=xmlnode_insert_tag(m->packet->x,"error");
            xmlnode_put_attrib(error,"code","302");
            xmlnode_insert_cdata(error,servers[s_index],-1);
            jpacket_reset(m->packet);
            js_deliver(m->packet);
            return M_HANDLED;
        }
        return M_PASS;
    }
    s_index=get_server(farm_size,m->packet->to->user);
    /*if this is our packet, cool, */
    if(js_config_name(C_CHECK,servers[s_index])) 
    {
        /* make sure the right host name is in place */
        jid_set(m->packet->to,js__hostname,JID_SERVER);
        xmlnode_put_attrib(m->packet->x,"to",jid_full(m->packet->to));
        jpacket_reset(m->packet);
        return M_PASS;
    }


    /* otherwise, dump this packet to the right server */
    jid_set(m->packet->to,servers[s_index],JID_SERVER);
    xmlnode_put_attrib(m->packet->x,"to",jid_full(m->packet->to));
    jpacket_reset(m->packet);
    js_deliver(m->packet);
    return M_HANDLED;
}

mreturn mod_farm_cleanup(mapi m, void* arg)
{
    pool_free(p);
    return M_PASS;
}

void mod_farm(void)
{
    xmlnode farm=js_config("farm/ip");
    if(farm==NULL) return;
    p=pool_new();
    servers=pmalloc(p,(sizeof(char*)*MAX_SERVERS));
    memset(servers,0,(sizeof(char*)*MAX_SERVERS));
    while(farm!=NULL)
    {
        servers[farm_size++]=pstrdup(p,xmlnode_get_data(farm));
        farm=xmlnode_get_nextsibling(farm);
    }
    js_mapi_register(P_DELIVER,mod_farm_deliver,NULL);
    js_mapi_register(P_SHUTDOWN,mod_farm_cleanup,NULL);
}



