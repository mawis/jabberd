#include "jabberd.h"

xmlnode greymatter = NULL;

int configurate(char *file)
{
    /* CONFIGXML is the default name for the config file - defined by the build system */
    char def[] = CONFIGXML;
    char *realfile = (char *)def;

    /* if no file name is specified, fall back to the default file */
    if(file != NULL)
        realfile = file;

    /* read and parse file */
    greymatter = xmlnode_file(realfile);

    /* was the there a read/parse error? */
    if(greymatter == NULL)
    {
        printf("Configuration using %s failed\n",realfile);
        return 1;
    }

    return 0;
}

/* private config handler list */
typedef struct cfg_struct
{
    char *node;
    cfgene f;
    void *arg;
    struct cfg_struct *next;
} *cfg, _cfg;

cfg cfgenes = NULL;
pool cfgenes_p = NULL;

/* register a function to handle that node in the config file */
void cfreg(char *node, cfgene f, void *arg)
{
    cfg newg;

    /* if first time */
    if(cfgenes_p == NULL) cfgenes_p = pool_new();

    /* create and setup */
    newg = pmalloc_x(cfgenes_p, sizeof(_cfg), 0);
    newg->node = pstrdup(cfgenes_p,node);
    newg->f = f;
    newg->arg = arg;

    /* hook into global */
    newg->next = cfgenes;
    cfgenes = newg;
}

/* util to scan through registered config callbacks */
cfg cfget(char *node)
{
    cfg next = NULL;

    for(next = cfgenes; next != NULL && strcmp(node,next->node) != 0; next = next->next);

    return next;
}

/* execute configuration file */
int configo(int exec)
{
    /* loop through entire config, generating idnodes and executing the registered functions */
    /* if !exec, don't actually create the idnodes, registered function know that idnode == NULL means just check config */

    /* free cfgenes_p when done */

    return 0;
}

