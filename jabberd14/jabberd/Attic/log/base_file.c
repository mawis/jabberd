#include "jabberd.h"

result base_file_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_file_config validating configuration\n");
        return r_PASS;
    }

    printf("base_file_config performing configuration %s\n",xmlnode2str(x));
}

void base_file(void)
{
    printf("base_file loading...\n");

    register_config("file",base_file_config,NULL);
}