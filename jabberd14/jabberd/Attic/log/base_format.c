/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  Jabber
 *  Copyright (C) 1998-1999 The Jabber Team http://jabber.org/
 */

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
    register_phandler(id,o_PREDELIVER,base_format_modify,(void*)strdup(xmlnode_get_data(x)));
    return r_DONE;
}

void base_format(void)
{
    log_debug(ZONE,"base_format loading...\n");

    register_config("format",base_format_config,NULL);
}
