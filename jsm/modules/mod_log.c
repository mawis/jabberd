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

actually, on second thought... we already have lots in place for logging, couldn't we reuse <log type="session"> or something like that in jabberd?

*/


thread mod_log__session = NULL;
thread mod_log__packet = NULL;

/* if the logging thread dies */
void _mod_log_cleanup(void *arg)
{
    thread t = (thread)arg;

    if(t == mod_log__session)
    {
        mod_log__session = NULL;
        log_error("mod_log","Write to session log failed, disabling session logging!");
    }
    if(t == mod_log__packet)
    {
        mod_log__packet = NULL;
        log_error("mod_log","Write to packet log failed, disabling packet logging!");
    }
}

void mod_log_init()
{
    int fd;
    char *file;

    file = xmlnode_get_data(js_config(m->si,"log/session"));
    fd = open(file, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if(file == NULL || fd < 0)
    {
        if(file != NULL)
            log_error("mod_log","Unable to open session log file %s",file);
        return;
    }
    mod_log__session = tstream_new(fd,"sessionlogger",NULL,NULL,NULL);
    pool_cleanup(mod_log__session->p, _mod_log_cleanup, (void *)mod_log__session);

    file = xmlnode_get_data(js_config(m->si,"log/packet"));
    fd = open(file, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if(file == NULL || fd < 0)
    {
        if(file != NULL)
            log_error("mod_log","Unable to open packet log file %s",file);
        return;
    }
    mod_log__packet = tstream_new(fd,"packetlogger",NULL,NULL,NULL);
    pool_cleanup(mod_log__packet->p, _mod_log_cleanup, (void *)mod_log__packet);
}

/* logs session characteristics */
mreturn mod_log_session_end(mapi m, void *arg)
{
    static char log[1024];
    int size;
    time_t t;

    if(mod_log__session == NULL)
        return M_PASS;

    log_debug(ZONE,"creating session log entry");

    t = time(NULL);

    /* TIMESTAMP TOTALSECONDS PACKETSFROM PACKETSTO USER@HOST/RES */
    size = snprintf(log, 1024, "%s %d %d %d %s\n",
                    create_log_timestamp(),
                    (int)(t - m->s->started),
                    m->s->c_in,
                    m->s->c_out,
                    jid_full(m->s->id));

    tstream_write(mod_log__session,log,size);

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
    static char log[1024];
    int size;

    if(m->packet == NULL || mod_log__packet == NULL)
        return M_PASS;

    log_debug(ZONE,"what the heck?? creating packet log entry");

    /* PACKET TYPE FROM TO */
    size = snprintf(log, 1024, "test: %s %s %s %s %s: %s\n",
                    create_log_timestamp(),
                    _mod_log_ptype(m->packet->type),
                    _mod_log_null(xmlnode_get_attrib(m->packet->x,"type")),
                    _mod_log_null(jid_full(m->packet->from)),
                    _mod_log_null(jid_full(m->packet->to)),
		    _mod_log_null(xmlnode2str(m->packet->x)));

    tstream_write(mod_log__packet,log,size);

    return M_PASS;
}

/* log session */
mreturn mod_log_session(mapi m, void *arg)
{
    js_mapi_session(es_END, m->s, mod_log_session_end, NULL);

    return M_PASS;
}

void mod_log(jsmi si)
{
    log_debug(ZONE,"init");
    mod_log_init();
    if(mod_log__session != NULL)
        js_mapi_register(si,e_SESSION, mod_log_session, NULL);
    if(mod_log__packet != NULL)
        js_mapi_register(si,e_DELIVER, mod_log_packet, NULL);
}

