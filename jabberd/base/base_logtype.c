#include "jabberd.h"

result base_logtype_filter(instance id, dpacket p, void* arg)
{
    char* comparisontype = (char*)arg;
    char* packettype     = xmlnode_get_attrib(p->x, "type");

    if (comparisontype == NULL || packettype == NULL)
    {
        /* FIXME: this might not be an error if <log>'s don't require a type */
        printf("base_logtype_filter error: invalid data; unable to filter.\n");
        return r_ERR;
    }

    /* If comparison fails, return ok..*/
    if (strcmp(packettype, comparisontype) == 0)
    {
        return r_PASS;
    }

    /* Otherwise, the filter failed */
    return r_ERR;
}

result base_logtype_config(instance id, xmlnode x, void *arg)
{
    char* name = NULL;
    if(id == NULL)
    {
        /* Ensure that the name of the tag is either "notice", "warn", or "alert" */
        name = xmlnode_get_name(x);
        if (strcmp(name, "notice") && strcmp(name, "warn") && strcmp(name, "alert"))
        {
            printf("base_logtype_config error: invalid log type filter requested (%s)\n", name);
            return r_ERR;
        }
        
        printf("base_logtype_config validating configuration\n");
        return r_PASS;
    }

    /* Register a conditional handler for this instance, passing the name
     * of the tag as an argument (for comparison in the filter op 
     * FIXME: don't know if should be strdup'ing */
    register_phandler(id, o_COND, base_logtype_filter, (void*)strdup(name));

    printf("base_logtype_config performing configuration %s\n",xmlnode2str(x));

    return r_PASS;
}

void base_logtype(void)
{
    printf("base_logtype loading...\n");

    register_config("notice",base_logtype_config,NULL);
    register_config("warn",base_logtype_config,NULL);
    register_config("alert",base_logtype_config,NULL);
}
