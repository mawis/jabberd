/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "License").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the License.  You
 * may obtain a copy of the License at http://www.jabber.com/license/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2000 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * --------------------------------------------------------------------------*/

#include "jabberd.h"
#define MAX_INCLUDE_NESTING 20
extern HASHTABLE cmd__line;
HASHTABLE instance__ids=NULL;

typedef struct shutdown_list
{
    pool p;
    shutdown_func f;
    void *arg;
    struct shutdown_list *next;
} _sd_list, *sd_list;
sd_list shutdown__list=NULL;

xmlnode greymatter__ = NULL;

void do_include(int nesting_level,xmlnode x)
{
    xmlnode cur;
    char message[MAX_LOG_SIZE];

    cur=xmlnode_get_firstchild(x);
    for(;cur!=NULL;)
    {
        if(cur->type!=NTYPE_TAG) 
        {
            cur=xmlnode_get_nextsibling(cur);
            continue;
        }
        if(j_strcmp(xmlnode_get_name(cur),"jabberd:include")==0)
        {
            xmlnode include;
            char *include_file=xmlnode_get_data(cur);
            xmlnode include_x=xmlnode_file(include_file);
            /* check for bad nesting */
            if(nesting_level>MAX_INCLUDE_NESTING)
            {
                snprintf(message, MAX_LOG_SIZE, "ERROR: Included files nested %d levels deep.  Possible Recursion\n",nesting_level);
                fprintf(stderr, "%s\n", message);
                exit(1);
            }
            include=cur;
            xmlnode_hide(include);
            /* check to see what to insert...
             * if root tag matches parent tag of the <include/> -- firstchild
             * otherwise, insert the whole file
             */
             if(j_strcmp(xmlnode_get_name(xmlnode_get_parent(cur)),xmlnode_get_name(include_x))==0)
                xmlnode_insert_node(x,xmlnode_get_firstchild(include_x));
             else
                xmlnode_insert_node(x,include_x);
             do_include(nesting_level+1,include_x);
             cur=xmlnode_get_nextsibling(cur);
             continue;
        }
        else 
        {
            do_include(nesting_level,cur);
        }
        cur=xmlnode_get_nextsibling(cur);
    }
}

void cmdline_replace(xmlnode x)
{
    char *flag;
    char *replace_text;
    xmlnode cur=xmlnode_get_firstchild(x);

    for(;cur!=NULL;cur=xmlnode_get_nextsibling(cur))
    {
        if(cur->type!=NTYPE_TAG)continue;
        if(j_strcmp(xmlnode_get_name(cur),"jabberd:cmdline")!=0)
        {
            cmdline_replace(cur);
            continue;
        }
        flag=xmlnode_get_attrib(cur,"flag");
        replace_text=ghash_get(cmd__line,flag);
        if(replace_text==NULL) replace_text=xmlnode_get_data(cur);

        xmlnode_hide(xmlnode_get_firstchild(x));
        xmlnode_insert_cdata(x,replace_text,-1);
        break;
    }
}

int configurate(char *file)
{
    /* XXX-temas:  do this one */
    /* CONFIGXML is the default name for the config file - defined by the build system */
    char def[] = CONFIGXML;
    char *realfile = (char *)def;
    char message[MAX_LOG_SIZE];

    /* if no file name is specified, fall back to the default file */
    if(file != NULL)
        realfile = file;

    /* read and parse file */
    greymatter__ = xmlnode_file(realfile);

    /* was the there a read/parse error? */
    if(greymatter__ == NULL)
    {
        snprintf(message, MAX_LOG_SIZE, "Configuration using %s failed\n",realfile);
        fprintf(stderr, "%s\n", message);
        return 1;
    }

    /* check greymatter for additional includes */
    do_include(0,greymatter__);
    cmdline_replace(greymatter__);

    return 0;
}

int config_reload(char *file)
{
    xmlnode old_config=greymatter__;
    int retval=configurate(file);

    if(retval) /* failed to load config */
    {
        greymatter__=old_config; /* restore old config */
        return 1;
    }
    else
    {
        xmlnode_free(old_config); /* free the old config */
        return 0;
    }
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

void _cfhandlers_cleanup(void *arg)
{
    pool_free(cfhandlers__p);
}

/* register a function to handle that node in the config file */
void register_config(char *node, cfhandler f, void *arg)
{
    cfg newg;

    /* if first time */
    if(cfhandlers__p == NULL) 
    {
        cfhandlers__p = pool_new();
        register_shutdown(_cfhandlers_cleanup,NULL);
    }

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

/* 
 * walk through the instance HASH, and cleanup the instances
 */
int _instance_cleanup(void *arg,const void *key,void *data)
{
    instance i=(instance)data;
    unregister_instance(i,i->id);
    while(i->hds)
    {
        handel h=i->hds->next;
        pool_free(i->hds->p);
        i->hds=h;
    }
    pool_free(i->p);
    return 1;
}

void config_cleanup(void)
{
    /* remove all the instances */
    ghash_walk(instance__ids,_instance_cleanup,NULL);
    ghash_destroy(instance__ids);
}

/* execute configuration file */
int configo(int exec)
{
    cfg c;
    xmlnode curx, curx2;
    ptype type;
    instance newi = NULL;
    pool p;
    char message[MAX_LOG_SIZE];

    if(instance__ids==NULL)
        instance__ids=ghash_create(20,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);

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
            snprintf(message, MAX_LOG_SIZE, "Configuration error in:\n%s\n",xmlnode2str(curx));
            fprintf(stderr, "%s\n", message);
            if(type==p_NONE) {
	    	snprintf(message, MAX_LOG_SIZE, "ERROR: Invalid Tag type: %s\n",xmlnode_get_name(curx));
	    	fprintf(stderr, "%s\n", message);
	    }
            if(xmlnode_get_attrib(curx,"id")==NULL){
            	snprintf(message, MAX_LOG_SIZE, "ERROR: Section needs an 'id' attribute\n");
                fprintf(stderr, "%s\n", message);
	    }
            if(xmlnode_get_firstchild(curx)==NULL){
                snprintf(message, MAX_LOG_SIZE, "ERROR: Section Has no data in it\n");
                fprintf(stderr, "%s\n", message);
	    }
            return 1;
	   
        }

        newi=ghash_get(instance__ids,xmlnode_get_attrib(curx,"id"));
        if(newi!=NULL)
        {
            snprintf(message, MAX_LOG_SIZE, "ERROR: Multiple Instances with same id: %s\n",xmlnode_get_attrib(curx,"id"));
            fprintf(stderr, "%s\n", message);
            exit(1);
        }

        /* create the instance */
        if(exec)
        {
            jid temp;
            p = pool_new();
            newi = pmalloc_x(p, sizeof(_instance), 0);
            newi->id = pstrdup(p,xmlnode_get_attrib(curx,"id"));
            newi->type = type;
            newi->p = p;
            newi->x = curx;
            /* make sure the id is valid for a hostname */
            temp=jid_new(p,newi->id);
            if(temp==NULL||j_strcmp(temp->server,newi->id)!=0)
            {
                snprintf(message, MAX_LOG_SIZE, "ERROR: Invalid id name: %s\n",newi->id);
                fprintf(stderr, "%s\n", message);
                pool_free(p);
                exit(1);
            }

            ghash_put(instance__ids,newi->id,newi);
            register_instance(newi,newi->id);
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
                char *error=pstrdup(xmlnode_pool(curx2),xmlnode_get_attrib(curx2,"error"));
                xmlnode_hide_attrib(curx2,"error");
                snprintf(message, MAX_LOG_SIZE, "Invalid Configuration in instance '%s':\n%s\n",xmlnode_get_attrib(curx,"id"),xmlnode2str(curx2));
                fprintf(stderr, "%s\n", message);
                if(c==NULL) {
			snprintf(message, MAX_LOG_SIZE, "ERROR: Unknown Base Tag: %s\n",xmlnode_get_name(curx2));
			fprintf(stderr, "%s\n", message);
		}
                else if(error!=NULL)
                {
                    snprintf(message, MAX_LOG_SIZE, "ERROR: Base Handler Returned an Error:\n%s\n",error);
                    fprintf(stderr, "%s\n", message);
                }
                return 1;
            }
        }
    }

    return 0;
}

void shutdown_callbacks(void)
{
    while(shutdown__list)
    {
        sd_list s=shutdown__list->next;
        (*shutdown__list->f)(shutdown__list->arg);
        pool_free(shutdown__list->p);
        shutdown__list=s;
    }
}

void register_shutdown(shutdown_func f,void *arg)
{
    pool p;
    sd_list new;
    if(f==NULL) return;
    
    p=pool_new();
    new=pmalloco(p,sizeof(_sd_list));
    new->p=p;
    new->f=f;
    new->arg=arg;
    new->next=shutdown__list;
    shutdown__list=new;
}
