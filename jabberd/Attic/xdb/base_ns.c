#include "jabberd.h"

result base_ns_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_ns_config validating configuration\n");
        return r_PASS;
    }

    printf("base_ns_config performing configuration %s\n",xmlnode2str(x));
}

void base_ns(void)
{
    printf("base_ns loading...\n");

    register_config("ns",base_ns_config,NULL);
}