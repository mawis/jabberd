#include "jabberd.h"

result base_cache_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_cache_config validating configuration\n");
        return r_PASS;
    }

    printf("base_cache_config performing configuration %s\n",xmlnode2str(x));

    return r_PASS;
}

void base_cache(void)
{
    printf("base_cache loading...\n");

    register_config("cache",base_cache_config,NULL);
}