#include "jabberd.h"

/* seperate ports for each section, hostnames validated */
/* the connected app normaly gets all packets delivered to it, but can connect again and only send (but in the same name) */
/* if registered as * for the host, then any name can be used as sender, and module delivers appropriately */
/* module must scan config for <host/> elements and configure itself appropriately */

/* each <accept> can contain an additional <host> section that will limit it to accepting those hosts w/ that secret, but they must exist at the parent level as well (as likely in <host/>) */

/* each instance can share ports */

/* struct that contains meta-info for each accept: instance, host (start local, then parent, is a list) */

result base_accept_config(instance id, xmlnode x, void *arg)
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

    register_config("accept",base_accept_config,NULL);
}