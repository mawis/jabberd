/* --------------------------------------------------------------------------
 *
 *  jabberd 1.4.4 GPL - XMPP/Jabber server implementation
 *
 *  Copyrights
 *
 *  Portions created by or assigned to Jabber.com, Inc. are
 *  Copyright (C) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 *  information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 *  Portions Copyright (C) 1998-1999 Jeremie Miller.
 *
 *
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  Special exception for linking jabberd 1.4.4 GPL with OpenSSL:
 *
 *  In addition, as a special exception, you are allowed to link the code
 *  of jabberd 1.4.4 GPL with the OpenSSL library (or with modified versions
 *  of OpenSSL that use the same license as OpenSSL), and distribute linked
 *  combinations including the two. You must obey the GNU General Public
 *  License in all respects for all of the code used other than OpenSSL.
 *  If you modify this file, you may extend this exception to your version
 *  of the file, but you are not obligated to do so. If you do not wish
 *  to do so, delete this exception statement from your version.
 *
 * --------------------------------------------------------------------------*/

#include "jabberd.h"

result base_format_modify(instance id, dpacket p, void *arg)
{
    char  *cur, *nxt, *f;
    pool  sp;
    spool log_result;

    if(id == NULL || p == NULL) 
        return r_ERR;

    /*  base format params:
        %h: host
        %t: type
        %d: date
        %s: body
    */

    sp=pool_new();

    f = pstrdup(sp, (char*)arg);
    log_result = spool_new(sp);

    cur = f;
    nxt = strchr(f, '%');
    
    if(nxt == NULL)
        spooler(log_result, f, log_result);
    
    while(nxt != NULL)
    {
        nxt[0] = '\0'; 
        
        if(cur != nxt)
            spooler(log_result, cur, log_result);
        
        nxt++;
        
        switch(nxt[0])
        {
        case 'h':
            spooler(log_result, xmlnode_get_attrib(p->x, "from"), log_result);
            break;
        case 't':
            spooler(log_result, xmlnode_get_attrib(p->x, "type"), log_result);
            break;
        case 'd':
            spooler(log_result, jutil_timestamp(), log_result);
            break;
        case 's':
            spooler(log_result, xmlnode_get_data(p->x), log_result);
            break;
        default:
            log_debug2(ZONE, LOGT_CONFIG|LOGT_STRANGE, "Invalid argument: %s", nxt[0]);
        }
        
        cur = ++nxt;
        nxt = strchr(cur, '%');
    }

    xmlnode_hide(xmlnode_get_firstchild(p->x));
    xmlnode_insert_cdata(p->x, spool_print(log_result), -1);

    pool_free(sp);
    return r_PASS;
}

result base_format_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        log_debug2(ZONE, LOGT_CONFIG|LOGT_INIT, "base_format_config validating configuration");
        if(xmlnode_get_data(x) == NULL)
        {
            log_debug2(ZONE, LOGT_CONFIG|LOGT_INIT|LOGT_STRANGE, "base_format invald format");
            xmlnode_put_attrib(x, "error", "'format' tag must contain a format string:\nUse %h to insert Hostname\nUse %t to insert Type of Log (notice,warn,alert)\nUse %d to insert Timestamp\nUse %s to insert the body of the message\n\nExample: '[%t] - %h - %d: %s'");
            return r_ERR;
        }
        return r_PASS;
    }
    
    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_format configuring instance %s ", id->id);

    if(id->type != p_LOG)
    {
        log_alert(NULL, "ERROR in instance %s: <format>..</format> element only allowed in log sections", id->id);
        return r_ERR;
    }

    register_phandler(id, o_PREDELIVER, base_format_modify, (void*)xmlnode_get_data(x));

    return r_DONE;
}

void base_format(void)
{
    log_debug2(ZONE, LOGT_INIT, "base_format loading...");
    register_config("format",base_format_config,NULL);
}
