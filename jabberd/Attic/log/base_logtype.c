#include "jabberd.h"

result base_logtype_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_logtype_config validating configuration\n");
        return r_PASS;
    }

    printf("base_logtype_config performing configuration %s\n",xmlnode2str(x));
}

void base_logtype(void)
{
    printf("base_logtype loading...\n");

    register_config("notice",base_logtype_config,NULL);
    register_config("warn",base_logtype_config,NULL);
    register_config("alert",base_logtype_config,NULL);
}
