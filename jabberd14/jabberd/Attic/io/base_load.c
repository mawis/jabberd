#include "jabberd.h"

/* typedef struct for symbol cache */

/* process entire load element, loading each one (unless already cached) */
/* if all loaded, exec each one in order */

/* they register a handler to accept incoming xmlnodes that get delivered to them */
/* base_load sends packets on when it receives them */

result base_load_config(idnode id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_load_config validating configuration\n");
        return r_PASS;
    }

    printf("base_load_config performing configuration %s\n",xmlnode2str(x));
}

void base_load(void)
{
    printf("base_load loading...\n");

    cfreg("load",base_load_config,NULL);
}