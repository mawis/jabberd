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
        log_debug(ZONE,"base_format_config validating configuration\n");
        if(xmlnode_get_data(x)==NULL)
        {
            xmlnode_put_attrib(x,"error","'format' tag must contain a format string:\nUse %h to insert Hostname\nUse %t to insert Type of Log (notice,warn,alert)\nUse %d to insert Timestamp\nUse %s to insert the body of the message\n\nExample: '[%t] - %h - %d: %s'");
            log_debug(ZONE,"base_format invald format");
            return r_ERR;
        }
        return r_PASS;
    }

    /* XXX this is an ugly hack, but it's better than a bad config */
    /* XXX needs to be a way to validate this in the checking phase */
    if(id->type!=p_LOG)
    {
        fprintf(stderr,"ERROR: <format>..</format> element only allowed in log sections\n");
        exit(1);
    }

    log_debug(ZONE,"base_format_config performing configuration %s\n",xmlnode2str(x));
    register_phandler(id,o_PREDELIVER,base_format_modify,(void*)xmlnode_get_data(x));
    return r_DONE;
}

void base_format(void)
{
    log_debug(ZONE,"base_format loading...\n");

    register_config("format",base_format_config,NULL);
}
