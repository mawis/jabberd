#include "jabberd.h"

/* theoretically, by including a <fork/> in a section, that instance would run via a seperate process and talk over an internal socket */
/* this is hard and not immediately useful (if ever) */

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