#include "jabberd.h"

extern xmlnode greymatter__;

/* private heartbeat ring struct */
typedef struct beat_struct
{
    beathandler f;
    void *arg;
    int freq;
    struct beat_struct *prev;
    struct beat_struct *next;
} *beat, _beat;

void *heartbeat(void *arg)
{
    /* start heartbeat thread, get frequency from config file, use arg as ring of registered heartbeats */
}

/* register a function to receive heartbeats */
void register_beat(int freq, beathandler f, void *arg)
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

        /* XXX-temas:  are these the only available types?  If not do we want
         * this in the configure stuff as well? */
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

