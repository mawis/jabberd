#include "jabberd.h"

result base_format_modify(instance id,dpacket p,void *arg)
{
    char *cur,*nxt,*f;
    pool sp;
    spool log_result;

    if(id==NULL||p==NULL) return r_ERR;

    /*  %h: host
        %t: type
        %d: date
        %s: body
    */

    sp=pool_new();
    f=pstrdup(sp,(char*)arg);
    log_result=spool_new(sp);

    cur=f;
    nxt=strchr(f,'%');
    if(nxt==NULL)
        spooler(log_result,f,log_result);
    while(nxt!=NULL)
    {
        nxt[0]='\0'; 
        if(cur!=nxt)
            spooler(log_result,cur,log_result);
        nxt++;
        switch(nxt[0])
        {
        case 'h':
            spooler(log_result,xmlnode_get_attrib(p->x,"from"),log_result);
            break;
        case 't':
            spooler(log_result,xmlnode_get_attrib(p->x,"type"),log_result);
            break;
        case 'd':
            spooler(log_result,jutil_timestamp(),log_result);
            break;
        case 's':
            spooler(log_result,xmlnode_get_data(p->x),log_result);
            break;
        default:
            log_debug(ZONE,"Invalid argument: %s",nxt[0]);
        }
        cur=++nxt;
        nxt=strchr(cur,'%');
    }

    xmlnode_hide(xmlnode_get_firstchild(p->x));
    xmlnode_insert_cdata(p->x,spool_print(log_result),-1);

    pool_free(sp);
    return r_PASS;
}

result base_format_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_format_config validating configuration\n");
        if(xmlnode_get_data(x)==NULL)
        {
            printf("base_format invald format");
            return r_ERR;
        }
        return r_PASS;
    }

    printf("base_format_config performing configuration %s\n",xmlnode2str(x));
    register_phandler(id,o_MODIFY,base_format_modify,(void*)xmlnode_get_data(x));
    return r_OK;
}

void base_format(void)
{
    printf("base_format loading...\n");

    register_config("format",base_format_config,NULL);
}
