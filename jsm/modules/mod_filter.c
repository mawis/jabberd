#include "jserver.h"

/*
* mod_filter.c: it's alive! it now handles all functions that
                used to be handled by mod_offline.c 
                mod_filter supports the following conditions:
                  unavailable - matches when you aren't online
                  from        - matches if the sender is the same
                                as the cdata in the <from/> tag
                  resource    - matches YOUR resource
                  subject     - matches the subject of the message
                  body        - matches the body of the message
                  show        - matches your <show/> in presence
                  type        - matches the type='' attrib
                and the following Actions:
                  offline     - stores the message offline
                  forward     - forwards the message to another jid
                  reply       - sends back an auto-reply message to
                                the sender
                  continue    - continues processing of other rules
                  settype     - change the incoming message type

                you may specify any number of conditions/actions,
                if there are more than one condition, ALL conditions
                must match for the rule to match, and ALL the listed
                actions will be taken.

                rules are checked in order, stopping when a match is
                found, unless a <continue/> flag is in place

                example rule:
                  <rule>
                    <unavailable/>
                    <offline/>
                    <reply>I'm not available right now</reply>
                    <forward>tsbandit@jabber.org</forward>
                  </rule>
*/

/* mod_filter must go first in module ordering */

/* basic principle of mod_filter
 * each user has their own filter
 * each filter contains zero or more rules
 * each rule contains one or more conditions and one or more actions
 * some conditions/actions may contain text to limit it further
 * first matching condition is applied and processing quits (unless an action is continue)
 * processed in order from client
 * NO ACTION IMPLIES DROP
 * FUTURE CONDITIONS: type, time, size
 * FUTURE ACTIONS: edit,error,settype
 */

xmlnode mod_filter__default = NULL;

/* get the user's filter rules */
xmlnode mod_filter_get(udata u)
{
    xmlnode ret;

    log_debug(ZONE,"getting %s's rules",u->user);

    /* get the existing rules */
    ret = js_xdb_get(u, NS_FILTER);
    if(ret == NULL)
    {
        log_debug(ZONE,"using default rules");
        ret = mod_filter__default;
    }

    log_debug(ZONE,"returning the rule set");
    return ret;
}

/* get the user's offline data */
xmlnode mod_filter_get_offline(udata u)
{
    xmlnode ret;

    log_debug(ZONE,"getting %s's offline data",u->user);

    /* get the existing */
    ret = js_xdb_get(u, NS_OFFLINE);
    if(ret == NULL)
    {
        log_debug(ZONE,"creating offline container");
        ret = xmlnode_new_tag("offline");
        xmlnode_put_attrib(ret,"xmlns",NS_OFFLINE);
        js_xdb_set(u,NS_OFFLINE,ret);
    }

    log_debug(ZONE,"returning the offline stuff");
    return ret;
}

void mod_filter_action_offline(mapi m,xmlnode rule)
{
    xmlnode opts=mod_filter_get_offline(m->user);
    log_debug(ZONE,"storing an offline message");
    jutil_delay(m->packet->x,"Offline Storage");
    xmlnode_insert_tag_node(opts,m->packet->x);
    js_xdb_set(m->user,NS_OFFLINE,opts);
}

void mod_filter_action_error(mapi m,xmlnode rule)
{
    log_debug(ZONE,"sending an error reply");
}

void mod_filter_action_reply(mapi m,xmlnode rule)
{
    char *reply=xmlnode_get_tag_data(rule,"reply");
    xmlnode x;
    jpacket p;

    if(reply==NULL) return;
    x=xmlnode_dup(m->packet->x);
    log_debug(ZONE,"sending back a custom reply");
    jutil_tofrom(x);
    if(xmlnode_get_tag(x,"body")!=NULL) xmlnode_hide(xmlnode_get_tag(x,"body"));
    xmlnode_insert_cdata(xmlnode_insert_tag(x,"body"),reply,-1);
    p=jpacket_new(x);
    js_deliver(p);
}

void mod_filter_action_forward(mapi m,xmlnode rule)
{
    char *forward=xmlnode_get_tag_data(rule,"forward");
    log_debug(ZONE,"forwarding message to %s",forward);
    if(forward!=NULL)
    {
        jpacket new=jpacket_new(xmlnode_dup(m->packet->x));
        xmlnode_put_attrib(new->x,"to",forward);
        jpacket_reset(new);
        js_deliver(new);
    }
}

void mod_filter_action_settype(mapi m,xmlnode rule)
{
    char *newtype=xmlnode_get_tag_data(rule,"settype");
    log_debug(ZONE,"changing message type to %s",newtype);
    if(newtype==NULL) return;
    xmlnode_put_attrib(m->packet->x,"type",newtype);
    jpacket_reset(m->packet);
}

mreturn mod_filter_handler(mapi m, void *arg)
{
    xmlnode rules;
    xmlnode x;
    int flag=0;
    int rule_count=1; /* for debugging purposes */
    jpacket p; /* for convienience */

    if(m->packet->type!=JPACKET_MESSAGE) return M_IGNORE;
    if(m->user==NULL) return M_PASS;
    if(m->variant==0) return M_PASS; /* ignore remote */
    p=m->packet;
    /* look through the user's rule set for a matching cond */
    log_debug(ZONE,"MAIN MOD_FILTER HANDLER");

    rules=xmlnode_get_firstchild(mod_filter_get(m->user));
    for(;rules!=NULL;rules=xmlnode_get_nextsibling(rules))
    {
        log_debug(ZONE,"looking at rule #%d",rule_count++);
        if(xmlnode_get_tag(rules,"unavailable")!=NULL)
            if(js_session_primary(m->user)!=NULL) continue;
        if(xmlnode_get_tag(rules,"from")!=NULL)
        {
            char *from=xmlnode_get_tag_data(rules,"from");
            if(from==NULL) continue;
            if(strcasecmp(from,jid_full(p->from))!=0) continue;
        }
        if(xmlnode_get_tag(rules,"resource")!=NULL)
        {
            char *res=xmlnode_get_tag_data(rules,"resource");
            if(res==NULL||p->to->resource==NULL) continue;
            if(strcasecmp(res,p->to->resource)!=0) continue;
        }
        if(xmlnode_get_tag(rules,"subject")!=NULL)
        {
            char *subject=xmlnode_get_tag_data(rules,"subject");
            if(subject==NULL||xmlnode_get_tag_data(p->x,"subject")==NULL) continue;
            if(strcasecmp(subject,xmlnode_get_tag_data(p->x,"subject"))!=0) continue;
        }
        if(xmlnode_get_tag(rules,"body")!=NULL)
        {
            char *body=xmlnode_get_tag_data(rules,"body");
            if(body==NULL||xmlnode_get_tag_data(p->x,"body")==NULL) continue;
            if(strcasecmp(body,xmlnode_get_tag_data(p->x,"body"))!=0) continue;
        }
        if(xmlnode_get_tag(rules,"show")!=NULL)
        {
            char *show=xmlnode_get_tag_data(rules,"show");
            if(show==NULL||j_strcmp(show,xmlnode_get_tag_data(m->s->presence,"show"))!=0) continue;
        }
        if(xmlnode_get_tag(rules,"type")!=NULL)
        {
            char norm[7]="normal\0";
            char *type=xmlnode_get_tag_data(rules,"type");
            char *xtype=xmlnode_get_attrib(p->x,"type");
            if(xtype==NULL) xtype=norm;
            if(type==NULL||j_strcmp(type,xtype)!=0) continue;
        }
        /* if we get here, this rule matches the conditions */
        log_debug(ZONE,"FOUND A MATCHING RULE");

        if(xmlnode_get_tag(rules,"settype")!=NULL)
        {
            flag=1;
            mod_filter_action_settype(m,rules);
        }
        if(xmlnode_get_tag(rules,"reply")!=NULL)
        {
            flag=1;
            mod_filter_action_reply(m,rules);
        }
        if(xmlnode_get_tag(rules,"forward")!=NULL)
        {
            flag=1;
            mod_filter_action_forward(m,rules);
        }
        if(xmlnode_get_tag(rules,"offline")!=NULL)
        {
            flag=1;
            mod_filter_action_offline(m,rules);
        }
        if(xmlnode_get_tag(rules,"continue")!=NULL) 
        {
            flag=0;
            continue;
        }
        if(flag==0)
        { /* no action implies drop */
            log_debug(ZONE,"No action -- dropping packet");
            xmlnode_free(p->x);
            return M_HANDLED;
        }
        break;
    }
    log_debug(ZONE,"done looking at rules with flag of %d",flag);
    if(flag==1) 
    {
        log_debug(ZONE,"returning M_HANDLED");
        xmlnode_free(p->x);
        return M_HANDLED;
    }
    else 
    {
        if(m->s==NULL) m->s=js_session_primary(m->user);
        if(m->s!=NULL)
        { /* last chance to handle the packet */
            log_debug(ZONE, "delivered to an active session");
            js_session_to(m->s,p);
            return M_HANDLED;
        }
    }
    log_debug(ZONE,"returning M_PASS");
    return M_PASS;
}

/* watches for when the user is available and sends out offline messages */
void mod_filter_offline_check(mapi m)
{
    xmlnode opts;
    xmlnode message;
    jpacket jp;
    xmlnode rules, rule;

    log_debug("mod_filter","avability established, check for messages");

    
    rules = mod_filter_get(m->user);

    opts=mod_filter_get_offline(m->user);
    /* check for ones saved for this resource */
    for(message=xmlnode_get_firstchild(opts);message!=NULL;message=xmlnode_get_nextsibling(message))
    {
        if(j_strcmp(xmlnode_get_name(message),"message")!=0) continue;
        js_session_to(m->s,jpacket_new(xmlnode_dup(message)));
        xmlnode_hide(message);
    }
    /* messages are gone, save the new sun-dried opts container */
    js_xdb_set(m->user, NS_OFFLINE, opts);
}

mreturn mod_filter_iq(mapi m)
{
    xmlnode opts;

    if(!NSCHECK(m->packet->iq,NS_FILTER)||m->packet->to!=NULL)
        return M_PASS;
    switch(jpacket_subtype(m->packet))
    {
    case JPACKET__SET:
        log_debug(ZONE,"handling a set request");
        js_xdb_set(m->user,NS_FILTER,xmlnode_dup(m->packet->iq));
        jutil_iqresult(m->packet->x);
        xmlnode_hide(m->packet->iq);
        jpacket_reset(m->packet);
        js_session_to(m->s,m->packet);
        break;
    case JPACKET__GET:
        log_debug(ZONE,"handling a get request");
        opts=mod_filter_get(m->user);
        xmlnode_put_attrib(m->packet->x,"type","result");
        xmlnode_insert_node(m->packet->iq,xmlnode_get_firstchild(opts));
        jpacket_reset(m->packet);
        js_session_to(m->s,m->packet);
        break;
    default:
        xmlnode_free(m->packet->x);
    }
    return M_HANDLED;
}

mreturn mod_filter_out(mapi m, void *arg)
{
    switch(m->packet->type)
    {
    case JPACKET_PRESENCE:
        switch(jpacket_subtype(m->packet))
        {
        case JPACKET__AVAILABLE:
            if(m->s->priority<0&&m->packet->to==NULL)
                mod_filter_offline_check(m);
            break;
        }
        break;
    case JPACKET_IQ:
        return mod_filter_iq(m);
        break;
    default:
        return M_IGNORE;
    }
    return M_PASS;
}

/* sets up the per-session listeners */
mreturn mod_filter_session(mapi m, void *arg)
{
    log_debug(ZONE,"session init");

    js_mapi_session(PS_OUT,m->s,mod_filter_out,NULL);

    return M_PASS;
}

void mod_filter(void)
{
    xmlnode rule;

    log_debug(ZONE,"init");
    js_mapi_register(P_DELIVER, mod_filter_handler, NULL);
    js_mapi_register(P_OFFLINE, mod_filter_handler, NULL);
    js_mapi_register(P_SESSION, mod_filter_session, NULL);

    /* setup the default built-in rule */
    mod_filter__default = xmlnode_new_tag("query");
    xmlnode_put_attrib(mod_filter__default,"xmlns",NS_FILTER);
    rule = xmlnode_insert_tag(mod_filter__default,"rule");
    xmlnode_insert_tag(rule,"unavailable");
    xmlnode_insert_tag(rule,"offline");

}

