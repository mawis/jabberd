#include "jabberd.h"

result base_format_config(idnode id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_format_config validating configuration\n");
        return r_PASS;
    }

    printf("base_format_config performing configuration %s\n",xmlnode2str(x));
}

void base_format(void)
{
    printf("base_format loading...\n");

    cfreg("format",base_format_config,NULL);
}