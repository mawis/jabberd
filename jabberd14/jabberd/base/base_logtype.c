#include "jabberd.h"

result base_logtype_config(idnode id, xmlnode x, void *arg)
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

    cfreg("notice",base_logtype_config,NULL);
    cfreg("warn",base_logtype_config,NULL);
    cfreg("alert",base_logtype_config,NULL);
}
