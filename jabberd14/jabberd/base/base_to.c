#include "jabberd.h"

result base_to_deliver(instance id,dpacket p,void* arg)
{
    char* log_data=xmlnode_get_data(p->x);
    xmlnode message;

    if(log_data==NULL)
        return r_ERR;

    message=xmlnode_new_tag("message");
    xmlnode_insert_cdata(message,log_data,-1);
    xmlnode_put_attrib(message,"from",xmlnode_get_attrib(p->x,"from"));
    xmlnode_put_attrib(message,"to",(char*)arg);
    deliver(dpacket_new(message),id);

    pool_free(p->p);
    return r_OK;
}

result base_to_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_to_config validating configuration\n");
        if(xmlnode_get_data(x)==NULL)
        {
            log_error(ZONE,"Invalid Configuration for base_to");
            return r_ERR;
        }
        return r_PASS;
    }

    register_phandler(id,o_DELIVER,base_to_deliver,(void*)strdup(xmlnode_get_data(x)));
    return r_OK;
}

void base_to(void)
{
    printf("base_to loading...\n");

    register_config("to",base_to_config,NULL);
}
