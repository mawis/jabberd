#include "jabberd.h"

/*
    <host>hostname.org</host>
    <host>.polld.isp.net</host> [the . flags any domain matching that]
    <host/>
*/

result base_host_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_host_config validating configuration %s\n",xmlnode2str(x));
        return r_PASS;
    }

    printf("base_host_config registering host %s with section '%s'\n",xmlnode_get_data(x), id->id);
    register_instance(id, xmlnode_get_data(x));

    return r_PASS;
}

void base_host(void)
{
    printf("base_host loading...\n");

    register_config("host",base_host_config,NULL);
}