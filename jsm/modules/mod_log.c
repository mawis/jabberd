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
#include "jsm.h"

/* XXX logging needs to be majorly rewritten for jsm

would be cool to do something like:
<log>
  <file>/foo/bar</file>
  <type>session</type> (or packet?)
  <format>%f %x %d</format> (whatever the vars are, you get the idea)
</log>

each section would create a thread that blocked on an mp
every time something needed to be logged, it would be sent via the mp to the thread(s)

actually, on second thought... we already have lots in place for logging, couldn't we reuse <log type="session"> or something like that in jabberd? maybe later :)

*/

/* container for logger vars */
typedef struct
{
    int fd;
    xmlnode cfg;
} *flogger, _flogger;


flogger mod_log_new(xmlnode cfg)
{
    flogger l;
    int fd = -1;
    char *file;

    file = xmlnode_get_tag_data(cfg,"file");
    if(file == NULL)
    {
        log_error(NULL,"No file configured for jsm logging");
        return NULL;
    }

    if(file != NULL)
        fd = open(file, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if(fd < 0)
    {
        log_error(NULL,"Unable to open jsm log file %s",file);
        return NULL;
    }

    l = pmalloco(xmlnode_pool(cfg),sizeof(_flogger));
    l->cfg = cfg;
    l->fd = fd;

    return l;
}

char *_mod_log_timestamp(void)
{
    time_t t;
    int sz;
    char *tmp_str;

    t = time(NULL);

    if(t == (time_t)-1)
        return NULL;

    tmp_str = ctime(&t);
    sz = strlen(tmp_str);
    /* chop off the \n */
    tmp_str[sz-1]=' ';

    return tmp_str;
}

/* logs session characteristics */
mreturn mod_log_session_end(mapi m, void *arg)
{
    flogger l = (flogger)arg;
    static char log[1024];
    int size;
    time_t t;

    log_debug(ZONE,"creating session log entry");

    t = time(NULL);

    /* TIMESTAMP TOTALSECONDS PACKETSFROM PACKETSTO USER@HOST/RES */
    size = snprintf(log, 1023, "%s %d %d %d %s\n",
                    _mod_log_timestamp(),
                    (int)(t - m->s->started),
                    m->s->c_in,
                    m->s->c_out,
                    jid_full(m->s->id));

    log[size] = '\0';

    /* actually log it */

    if(l->fd == -1)
    { /* fd is dead */
        log_notice(m->s->id->server,"failed session log message: %s",log);
        return M_PASS;
    }
    if(pth_write(l->fd, log, size) <= 0)
    { /* when logging fails */
        log_error(m->s->id->server,"jsm logging to %s failed: %s",xmlnode_get_tag(l->cfg,"file"),strerror(errno));
        close(l->fd);
        l->fd = -1;
    }

    return M_PASS;
}

char *_mod_log_ptype(int type)
{
    static char ret[10];

    ret[0] = '\0';
    switch(type)
    {
    case JPACKET_MESSAGE:
        strcat(ret,"message");
        break;
    case JPACKET_PRESENCE:
        strcat(ret,"presence");
        break;
    case JPACKET_IQ:
        strcat(ret,"iq");
        break;
    case JPACKET_S10N:
        strcat(ret,"s10n");
        break;
    }

    return (char *)ret;
}

char *_mod_log_null(char *data)
{
    static char ret[] = "-";

    if(data == NULL)
        return (char *)ret;
    else
        return data;
}

/* logs packets */
mreturn mod_log_packet(mapi m, void *arg)
{
    flogger l = (flogger)arg;
    static char log[1024];
    int size;

    if(m->packet == NULL)
        return M_PASS;

    log_debug(ZONE,"what the heck?? creating packet log entry");

    /* PACKET TYPE FROM TO */
    size = snprintf(log, 1023, "test: %s %s %s %s %s: %s\n",
                    _mod_log_timestamp(),
                    _mod_log_ptype(m->packet->type),
                    _mod_log_null(xmlnode_get_attrib(m->packet->x,"type")),
                    _mod_log_null(jid_full(m->packet->from)),
                    _mod_log_null(jid_full(m->packet->to)),
		    _mod_log_null(xmlnode2str(m->packet->x)));

    log[size] = '\0';

    /* actually log it */

    if(l->fd == -1)
    { /* fd is dead */
        log_notice(m->packet->to->server,"failed session log message: %s",log);
        return M_PASS;
    }
    if(pth_write(l->fd, log, size) <= 0)
    { /* when logging fails */
        log_error(m->packet->to->server,"jsm logging to %s failed: %s",xmlnode_get_tag(l->cfg,"file"),strerror(errno));
        close(l->fd);
        l->fd = -1;
    }

    return M_PASS;
}

/* log session */
mreturn mod_log_session(mapi m, void *arg)
{
    js_mapi_session(es_END, m->s, mod_log_session_end, arg);

    return M_PASS;
}

void mod_log(jsmi si)
{
    xmlnode cur;
    flogger l;
    char *type;

    log_debug(ZONE,"init");

    for(cur = xmlnode_get_firstchild(js_config(si,NULL)); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        if(j_strcmp(xmlnode_get_name(cur),"log") != 0) continue;

        l = mod_log_new(cur);
        if(l == NULL) continue;

        type = xmlnode_get_tag_data(cur,"type");
        if(j_strcmp(type,"session") == 0)
        {
            js_mapi_register(si,e_SESSION, mod_log_session, (void *)l);
        }else if(j_strcmp(type,"packet") == 0){
            js_mapi_register(si,e_DELIVER, mod_log_packet, (void *)l);
        }else{
            log_error(NULL,"Illegal type '%s' configured for jsm logging",type);
        }
    }
}

