#include "jabberd.h"

result base_host_config(idnode id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_host_config validating configuration %s\n",xmlnode2str(x));
        return r_PASS;
    }

    printf("base_host_config registering host %s with section '%s'\n",xmlnode_get_data(x), id->id);
    idreg(id, xmlnode_get_data(x));
}

void base_host(void)
{
    printf("base_host loading...\n");

    cfreg("host",base_host_config,NULL);
}