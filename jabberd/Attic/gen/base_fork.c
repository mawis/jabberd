#include "jabberd.h"

result base_fork_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_fork_config validating configuration\n");
        return r_PASS;
    }

    printf("base_fork_config performing configuration %s\n",xmlnode2str(x));
}

void base_fork(void)
{
    printf("base_fork loading...\n");

    register_config("fork",base_fork_config,NULL);
}