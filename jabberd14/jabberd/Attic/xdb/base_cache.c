#include "jabberd.h"

result base_cache_config(idnode id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_cache_config validating configuration\n");
        return r_PASS;
    }

    printf("base_cache_config performing configuration %s\n",xmlnode2str(x));
}

void base_cache(void)
{
    printf("base_cache loading...\n");

    cfreg("cache",base_cache_config,NULL);
}