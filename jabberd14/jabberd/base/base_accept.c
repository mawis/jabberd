#include "jabberd.h"

/* seperate ports for each section, hostnames validated */
/* the connected app normaly gets all packets delivered to it, but can connect again and only send (but in the same name) */
/* if registered as * for the host, then any name can be used as sender, and module delivers appropriately */

result base_accept_config(idnode id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_accept_config validating configuration\n");
        return r_PASS;
    }

    printf("base_accept_config performing configuration %s\n",xmlnode2str(x));
}

void base_accept(void)
{
    printf("base_accept loading...\n");

    cfreg("accept",base_accept_config,NULL);
}