#include "jabberd.h"

result base_stderr_config(idnode id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_stderr_config validating configuration\n");
        return r_PASS;
    }

    printf("base_stderr_config performing configuration %s\n",xmlnode2str(x));
}

void base_stderr(void)
{
    printf("base_stderr loading...\n");

    cfreg("stderr",base_stderr_config,NULL);
}