#include "jabberd.h"

/* consult apache source to figure out how to do this */
/* fork/exec a command, serialize xmlnodes to its STDIN for incoming packets, read it's STDOUT as an xmlstream */

result base_exec_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_exec_config validating configuration\n");
        return r_PASS;
    }

    printf("base_exec_config performing configuration %s\n",xmlnode2str(x));
}

void base_exec(void)
{
    printf("base_exec loading...\n");

    register_config("exec",base_exec_config,NULL);
}