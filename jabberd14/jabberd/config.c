#include "jabberd.h"

xmlnode greymatter__ = NULL;

int configurate(char *file)
{
    /* CONFIGXML is the default name for the config file - defined by the build system */
    char def[] = CONFIGXML;
    char *realfile = (char *)def;

    /* if no file name is specified, fall back to the default file */
    if(file != NULL)
        realfile = file;

    /* read and parse file */
    greymatter__ = xmlnode_file(realfile);

    /* was the there a read/parse error? */
    if(greymatter__ == NULL)
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
    cfhandler f;
    void *arg;
    struct cfg_struct *next;
} *cfg, _cfg;

cfg cfhandlers__ = NULL;
pool cfhandlers__p = NULL;

/* register a function to handle that node in the config file */
void register_config(char *node, cfhandler f, void *arg)
{
    cfg newg;

    /* if first time */
    if(cfhandlers__p == NULL) cfhandlers__p = pool_new();

    /* create and setup */
    newg = pmalloc_x(cfhandlers__p, sizeof(_cfg), 0);
    newg->node = pstrdup(cfhandlers__p,node);
    newg->f = f;
    newg->arg = arg;

    /* hook into global */
    newg->next = cfhandlers__;
    cfhandlers__ = newg;
}

/* util to scan through registered config callbacks */
cfg cfget(char *node)
{
    cfg next = NULL;

    for(next = cfhandlers__; next != NULL && strcmp(node,next->node) != 0; next = next->next);

    return next;
}

/* execute configuration file */
int configo(int exec)
{
    cfg c;
    xmlnode curx, curx2;
    ptype type;
    instance newi = NULL;
    pool p;

    for(curx = xmlnode_get_firstchild(greymatter__); curx != NULL; curx = xmlnode_get_nextsibling(curx))
    {
        if(xmlnode_get_type(curx) != NTYPE_TAG || strcmp(xmlnode_get_name(curx),"base") == 0)
            continue;

        type = p_NONE;

        if(strcmp(xmlnode_get_name(curx),"log") == 0)
            type = p_LOG;
        if(strcmp(xmlnode_get_name(curx),"xdb") == 0)
            type = p_XDB;
        if(strcmp(xmlnode_get_name(curx),"service") == 0)
            type = p_NORM;

        if(type == p_NONE || xmlnode_get_attrib(curx,"id") == NULL || xmlnode_get_firstchild(curx) == NULL)
        {
            /* XXX be more helpful here */
            printf("Configuration error in:\n%s\n",xmlnode2str(curx));
            return 1;
        }

        /* create the instance */
        if(exec)
        {
            p = pool_new();
            newi = pmalloc_x(p, sizeof(_instance), 0);
            newi->id = pstrdup(p,xmlnode_get_attrib(curx,"id"));
            newi->type = type;
            newi->p = p;
            newi->x = curx;
        }

        /* loop through all this sections children */
        for(curx2 = xmlnode_get_firstchild(curx); curx2 != NULL; curx2 = xmlnode_get_nextsibling(curx2))
        {
            /* only handle elements in our namespace */
            if(xmlnode_get_type(curx2) != NTYPE_TAG || xmlnode_get_attrib(curx2, "xmlns") != NULL)
                continue;

            /* run the registered function for this element */
            c = cfget(xmlnode_get_name(curx2));
            if(c == NULL || (c->f)(newi, curx2, c->arg) == r_ERR)
            {
                /* XXX be more helpful here */
                printf("Configuration error in:\n%s\nSpecifically:\n%s\n",xmlnode2str(curx),xmlnode2str(curx2));
                return 1;
            }
        }
    }

    return 0;
}

