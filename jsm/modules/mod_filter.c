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
typedef struct action_struct 
{
    pool p;
    int is_match,has_action;
    int offline,reply,settype,cont;
    jid forward;
    mapi m;
} _action, *action;


/* get the user's filter rules */
xmlnode mod_filter_get(udata u)
{
    xmlnode ret;

    /* get the existing rules */
    ret = xdb_get(u->si->xc,u->id, NS_FILTER);
    if(ret == NULL)
    {
        ret = xmlnode_dup(mod_filter__default);
    }

    return ret;
}

/* get the user's offline data */
xmlnode mod_filter_get_offline(udata u)
{
    xmlnode ret;

    /* get the existing */
    ret = xdb_get(u->si->xc,u->id, NS_OFFLINE);
    if(ret == NULL)
    {
        ret = xmlnode_new_tag("offline");
        xmlnode_put_attrib(ret,"xmlns",NS_OFFLINE);
    }

    return ret;
}

void mod_filter_action_offline(mapi m,xmlnode rule)
{
    xmlnode opts,cur;
    int num_tags=0;
    static int max_offline = -1;

    /* only store normal, error, or chat */
    switch(jpacket_subtype(m->packet))
    {
    case JPACKET__NONE:
    case JPACKET__ERROR:
    case JPACKET__CHAT:
        break;
    default:
        return;
    }

    /* XXX this is a hack for now, global maxoffline setting across all instances */
    if(max_offline == -1)
        max_offline = j_atoi(xmlnode_get_data(js_config(m->si,"maxoffline")),100);

    opts=mod_filter_get_offline(m->user);
    for(cur=xmlnode_get_firstchild(opts);cur!=NULL;cur=xmlnode_get_nextsibling(cur))num_tags++;
    if(num_tags<max_offline)
    {
        jutil_delay(m->packet->x,"Offline Storage");
        xmlnode_insert_tag_node(opts,m->packet->x);
        xdb_set(m->si->xc,m->user->id,NS_OFFLINE,opts);
    }
    xmlnode_free(opts);
}

void mod_filter_action_error(mapi m,xmlnode rule)
{
    log_debug(ZONE,"sending an error reply");
}

void mod_filter_action_reply(mapi m,xmlnode rule)
{
    char *reply=xmlnode_get_tag_data(rule,"reply");
    xmlnode x;

    if(reply==NULL) return;
    x=xmlnode_dup(m->packet->x);
    jutil_tofrom(x);
    if(xmlnode_get_tag(x,"body")!=NULL) xmlnode_hide(xmlnode_get_tag(x,"body"));
    xmlnode_insert_cdata(xmlnode_insert_tag(x,"body"),reply,-1);
    deliver(dpacket_new(x),m->si->i);
}

void mod_filter_action_forward(mapi m,xmlnode rule,jid j)
{
    int has_envelope=0;
    jid cur;
    xmlnode x=xmlnode_get_tag(m->packet->x,"x?xmlns=jabber:x:envelope");

    /* check for infinite loops... */
    if(x!=NULL)
    {
        xmlnode cur=xmlnode_get_tag(x,"forwardedby");
        has_envelope=1;
        for(;cur!=NULL;cur=xmlnode_get_nextsibling(cur)) 
        {
            if(j_strcmp(xmlnode_get_name(cur),"forwardedby")==0)
            {
                char *fb=xmlnode_get_attrib(cur,"jid");
                jid j=jid_new(m->packet->p,fb);
                if(jid_cmpx(j,m->packet->to,JID_USER|JID_SERVER)==0)
                {
                    x=xmlnode_dup(m->packet->x);
                    xmlnode_put_attrib(x,"to",jid_full(j));
                    xmlnode_put_attrib(x,"from",jid_full(m->packet->to));
                    deliver_fail(dpacket_new(x),"Forwarding would result in infinite loop");
                    return;
                }
            }
        }
    }
    if(!has_envelope)
      xmlnode_put_attrib(x=xmlnode_insert_tag(m->packet->x,"x"),"xmlns","jabber:x:envelope");
    xmlnode_put_attrib(xmlnode_insert_tag(x,"forwardedby"),"jid",jid_full(m->packet->to));
    xmlnode_put_attrib(xmlnode_insert_tag(x,"from"),"jid",jid_full(m->packet->from));

    for(cur=j;cur!=NULL;cur=cur->next)
        xmlnode_put_attrib(xmlnode_insert_tag(x,"cc"),"jid",jid_full(cur));
    for(;j!=NULL;j=j->next)
    {
        x=xmlnode_dup(m->packet->x);
        xmlnode_put_attrib(x,"to",jid_full(j));
        xmlnode_put_attrib(x,"from",jid_full(m->packet->to));
        deliver(dpacket_new(x),m->si->i);
    }
}

void mod_filter_action_settype(mapi m,xmlnode rule)
{
    char *newtype=xmlnode_get_tag_data(rule,"settype");
    if(newtype==NULL) 
        xmlnode_hide_attrib(m->packet->x,"type");
    else
        xmlnode_put_attrib(m->packet->x,"type",newtype);
    jpacket_reset(m->packet);
}

mreturn mod_filter_handler(mapi m, void *arg)
{
    xmlnode rules,cur;
    xmlnode container;
    action cur_action;
    jpacket jp;
    pool p;

    jp=m->packet;
    if(m->packet->type!=JPACKET_MESSAGE) return M_IGNORE;

    switch(jpacket_subtype(m->packet))
    {
    case JPACKET__NONE:
    case JPACKET__ERROR:
    case JPACKET__CHAT:
        break;
    default:
        return M_PASS;
    }

    if(m->user==NULL) return M_PASS;
    p=pool_new();
    cur_action=pmalloc(p,sizeof(_action));
    memset(cur_action,0,sizeof(_action));
    /* look through the user's rule set for a matching cond */
    log_debug(ZONE,"Looking at rules");

    rules=xmlnode_get_tag(container=mod_filter_get(m->user),"rule");
    for(;rules!=NULL;rules=xmlnode_get_nextsibling(rules))
    {
        cur=xmlnode_get_firstchild(rules);
        for(;cur!=NULL;)
        {
        /* try to match this rule */
            if(j_strcmp(xmlnode_get_name(cur),"unavailable")==0)
            {
                log_debug(ZONE,"checking unavailalbe");    
                if(js_session_primary(m->user)==NULL)
                    cur_action->is_match=1;
                else
                    break;
                log_debug(ZONE,"MATCH!");
                cur=xmlnode_get_nextsibling(cur);
            }
            else if(j_strcmp(xmlnode_get_name(cur),"from")==0)
            {
                xmlnode f=cur;
                log_debug(ZONE,"checking from");
                cur_action->is_match=0;
                for(;f!=NULL;f=xmlnode_get_tag(rules,"from"))
                {
                    char *from=xmlnode_get_data(f);
                    log_debug(ZONE,"checking from: %s",from);
                    if(cur_action->is_match||from==NULL||jid_cmpx(jid_new(jp->from->p,from),jp->from,JID_USER|JID_SERVER)!=0)
                    {
                        log_debug(ZONE,"not a match, killing node");
                        if(cur==f)
                            cur=xmlnode_get_nextsibling(cur);
                        xmlnode_hide(f);
                        continue;
                    }
                    if(cur==f)cur=xmlnode_get_nextsibling(cur);
                    xmlnode_hide(f);
                    cur_action->is_match=1;
                }
                if(!cur_action->is_match) break;
                log_debug(ZONE,"MATCH!");
            }
            else if(j_strcmp(xmlnode_get_name(cur),"resource")==0)
            {
                xmlnode r=cur;
                log_debug(ZONE,"checking resource");
                cur_action->is_match=0;
                for(;r!=NULL;r=xmlnode_get_tag(rules,"resource"))
                {
                    char *res=xmlnode_get_data(r);
                    log_debug(ZONE,"checking res: %s",res);
                    if(cur_action->is_match||res==NULL||jp->to->resource==NULL||strcasecmp(res,jp->to->resource)!=0)
                    {
                        log_debug(ZONE,"not a match");
                        if(cur==r)
                            cur=xmlnode_get_nextsibling(cur);
                        xmlnode_hide(r);
                        continue;
                    }
                    if(cur==r)cur=xmlnode_get_nextsibling(cur);
                    xmlnode_hide(r);
                    cur_action->is_match=1;
                }
                if(!cur_action->is_match) break;
                log_debug(ZONE,"MATCH!");
            }
            else if(j_strcmp(xmlnode_get_name(cur),"subject")==0)
            {
                xmlnode s=cur;
                log_debug(ZONE,"checking subject");
                cur_action->is_match=0;
                for(;s!=NULL;s=xmlnode_get_tag(rules,"subject"))
                {
                    char *subject=xmlnode_get_data(s);
                    log_debug(ZONE,"checking subject: %s",subject);
                    if(cur_action->is_match||subject==NULL||xmlnode_get_tag_data(jp->x,"subject")==NULL||strcasecmp(subject,xmlnode_get_tag_data(jp->x,"subject"))!=0)
                    {
                        log_debug(ZONE,"not a match");
                        if(cur==s)cur=xmlnode_get_nextsibling(cur);
                        xmlnode_hide(s);
                        continue;
                    }
                    if(cur==s)cur=xmlnode_get_nextsibling(cur);
                    xmlnode_hide(s);
                    cur_action->is_match=1;
                }
                if(!cur_action->is_match) break;
                log_debug(ZONE,"MATCH!");
            }
            else if(j_strcmp(xmlnode_get_name(cur),"body")==0)
            {
                xmlnode b=cur;
                log_debug(ZONE,"checking body");
                cur_action->is_match=0;
                for(;b!=NULL;b=xmlnode_get_tag(rules,"body"))
                {
                    char *body=xmlnode_get_data(b);
                    log_debug(ZONE,"checking body: %s",body);
                    if(cur_action->is_match||body==NULL||xmlnode_get_tag_data(jp->x,"body")==NULL||strcasecmp(body,xmlnode_get_tag_data(jp->x,"body"))!=0)
                    {
                        log_debug(ZONE,"not a match");
                        if(cur==b)cur=xmlnode_get_nextsibling(cur);
                        xmlnode_hide(b);
                        continue;
                    }
                    if(cur==b)cur=xmlnode_get_nextsibling(cur);
                    xmlnode_hide(b);
                    cur_action->is_match=1;
                }
                if(!cur_action->is_match) break;
                log_debug(ZONE,"MATCH!");
            }
            else if(j_strcmp(xmlnode_get_name(cur),"show")==0)
            {
                xmlnode sh=cur;
                session s;
                if(m->packet->to->resource!=NULL)
                    s=js_session_get(m->user,m->packet->to->resource);
                else
                    s=js_session_primary(m->user);
                cur_action->is_match=0;
                for(;sh!=NULL;sh=xmlnode_get_tag(rules,"show"))
                {
                    char *show=xmlnode_get_data(sh);
                    log_debug(ZONE,"checking show: %s",show);
                    if(cur_action->is_match||show==NULL||s==NULL||j_strcmp(show,xmlnode_get_tag_data(s->presence,"show"))!=0)
                    {
                        log_debug(ZONE,"not a match");
                        if(cur==sh)cur=xmlnode_get_nextsibling(cur);
                        xmlnode_hide(sh);
                        continue;
                    }
                    if(cur==sh)cur=xmlnode_get_nextsibling(cur);
                    xmlnode_hide(sh);
                    cur_action->is_match=1;
                }
                if(!cur_action->is_match) break;
                log_debug(ZONE,"MATCH!");
            }
            else if(j_strcmp(xmlnode_get_name(cur),"type")==0)
            {
                xmlnode t=cur;
                char norm[7]="normal\0";
                char *xtype=xmlnode_get_attrib(jp->x,"type");
                log_debug(ZONE,"checking type");
                if(xtype==NULL) xtype=norm;
                cur_action->is_match=0;
                for(;t!=NULL;t=xmlnode_get_tag(rules,"type"))
                {
                    char *type=xmlnode_get_data(t);
                    log_debug(ZONE,"checking type: %s",type);
                    if(cur_action->is_match||(type==NULL&&jpacket_subtype(m->packet)!=JPACKET__NONE)||(j_strcmp(type,xtype)!=0))
                    {
                        log_debug(ZONE,"not a match");
                        if(cur==t)cur=xmlnode_get_nextsibling(cur);
                        xmlnode_hide(t);
                        continue;
                    }
                    if(cur==t)cur=xmlnode_get_nextsibling(cur);
                    xmlnode_hide(t);
                    cur_action->is_match=1;
                }
                if(!cur_action->is_match) break;
                log_debug(ZONE,"MATCH");
            }
            else if(j_strcmp(xmlnode_get_name(cur),"settype")==0)
            {
                cur_action->has_action=1;
                cur_action->settype=1;
                log_debug(ZONE,"settype: %s",xmlnode_get_data(cur));
                cur=xmlnode_get_nextsibling(cur);
            }
            else if(j_strcmp(xmlnode_get_name(cur),"reply")==0)
            {
                cur_action->has_action=1;
                cur_action->reply=1;
                log_debug(ZONE,"reply: %s",xmlnode_get_data(cur));
                cur=xmlnode_get_nextsibling(cur);
            }
            else if(j_strcmp(xmlnode_get_name(cur),"forward")==0)
            {
                jid new=jid_new(p,xmlnode_get_data(cur));
                cur_action->has_action=1;
                new->next=cur_action->forward;
                cur_action->forward=new;
                log_debug(ZONE,"forward: %s",xmlnode_get_data(cur));
                cur=xmlnode_get_nextsibling(cur);
            }
            else if(j_strcmp(xmlnode_get_name(cur),"offline")==0)
            {
                cur_action->has_action=1;
                cur_action->offline=1;
                log_debug(ZONE,"offline storage");
                cur=xmlnode_get_nextsibling(cur);
            }
            else if(j_strcmp(xmlnode_get_name(cur),"continue")==0) 
            {
                cur_action->has_action=1;
                cur_action->cont=1;
                log_debug(ZONE,"continue processing");
                cur=xmlnode_get_nextsibling(cur);
            }
            else
            {
                cur=xmlnode_get_nextsibling(cur);
            }
                    
        }
        if(!cur_action->is_match)
        {
            memset(cur_action,0,sizeof(_action));
            continue;    
        }
        if(!cur_action->has_action)
        {
            xmlnode_free(jp->x);
            pool_free(p);
            xmlnode_free(container);
            return M_HANDLED;
        }

        if(cur_action->reply)
            mod_filter_action_reply(m,rules);
        if(cur_action->settype)
            mod_filter_action_settype(m,rules);
        if(cur_action->forward!=NULL)
            mod_filter_action_forward(m,rules,cur_action->forward);
        if(cur_action->offline)
            mod_filter_action_offline(m,rules);
        if(cur_action->cont)
        { /* continue processing rules */
            memset(cur_action,0,sizeof(_action));
            continue;
        }
        else break;
    }
    xmlnode_free(container);
    if(cur_action->has_action) 
    {
        xmlnode_free(jp->x);
        pool_free(p);
        return M_HANDLED;
    }
    else 
    {
        session s=m->s;
        if(s==NULL) s=js_session_primary(m->user);
        if(s!=NULL)
        { /* last chance to handle the packet */
            js_session_to(s,jp);
            pool_free(p);
            return M_HANDLED;
        }
        else
        { /* no active session, and no matching rule, destroy this packet */
            xmlnode_free(m->packet->x);
            pool_free(p);
            return M_HANDLED;
        }
    }
    /* it will never get to this point, but just becuase... */
    return M_PASS;
}

/* watches for when the user is available and sends out offline messages */
void mod_filter_offline_check(mapi m)
{
    xmlnode opts;
    xmlnode message;

    log_debug("mod_filter","avability established, check for messages");

    
    /* check for ones saved for this resource */
    opts=mod_filter_get_offline(m->user);
    for(message=xmlnode_get_firstchild(opts);message!=NULL;message=xmlnode_get_nextsibling(message))
    {
        if(j_strcmp(xmlnode_get_name(message),"message")!=0) continue;
        js_session_to(m->s,jpacket_new(xmlnode_dup(message)));
        xmlnode_hide(message);
    }
    /* messages are gone, save the new sun-dried opts container */
    xdb_set(m->si->xc,m->user->id, NS_OFFLINE, opts);
    xmlnode_free(opts);
}

mreturn mod_filter_iq(mapi m)
{
    xmlnode opts;

    if(!NSCHECK(m->packet->iq,NS_FILTER)||m->packet->to!=NULL)
        return M_PASS;
    switch(jpacket_subtype(m->packet))
    {
    case JPACKET__SET:
        xdb_set(m->si->xc,m->user->id,NS_FILTER,m->packet->iq);
        jutil_iqresult(m->packet->x);
        xmlnode_hide(m->packet->iq);
        jpacket_reset(m->packet);
        js_session_to(m->s,m->packet);
        break;
    case JPACKET__GET:
        opts=mod_filter_get(m->user);
        xmlnode_put_attrib(m->packet->x,"type","result");
        xmlnode_insert_node(m->packet->iq,xmlnode_get_firstchild(opts));
        jpacket_reset(m->packet);
        js_session_to(m->s,m->packet);
        xmlnode_free(opts);
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
    log_debug(ZONE,"FILTER session init");

    js_mapi_session(es_OUT,m->s,mod_filter_out,NULL);

    return M_PASS;
}

void mod_filter(jsmi si)
{
    xmlnode rule;

    log_debug(ZONE,"FILTER init");
    js_mapi_register(si,e_DELIVER, mod_filter_handler, NULL);
    js_mapi_register(si,e_OFFLINE, mod_filter_handler, NULL);
    js_mapi_register(si,e_SESSION, mod_filter_session, NULL);

    /* setup the default built-in rule */
    mod_filter__default = xmlnode_new_tag("query");
    xmlnode_put_attrib(mod_filter__default,"xmlns",NS_FILTER);
    rule = xmlnode_insert_tag(mod_filter__default,"rule");
    xmlnode_put_attrib(rule,"name","default rule");
    xmlnode_insert_tag(rule,"unavailable");
    xmlnode_insert_tag(rule,"offline");
}

