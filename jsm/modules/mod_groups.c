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

#define NS_XGROUPS "jabber:xdb:groups"

typedef struct
{
    xdbcache xc;
    xht groups;
    xht config; /* hash of group specfic config */
    char *inst; /* register instructions */
} *mod_groups_i, _mod_groups_i;

typedef struct
{
    xht to;
    xht from;
} *grouptab, _grouptab;

xmlnode mod_groups_get(mod_groups_i mi, pool p, char *host, char *gid)
{
     xmlnode group, users;
     jid id;

     if (gid == NULL) return NULL;

     log_debug("mod_groups","checking config");

     /* check config for specfic group before xdb */
     group = (xmlnode) xhash_get(mi->config,gid);

     if (group != NULL)
     {
         users = xmlnode_get_tag(group,"users");
         if (users)
         {
             users = xmlnode_dup(users);
             xmlnode_insert_cdata(xmlnode_insert_tag(users,"name"),xmlnode_get_tag_data(group,"name"),-1);
             xmlnode_insert_tag(users,"static"); /* we can't change the users if they are in the config */
             return users;
         }
     }

     id = jid_new(p,host);
     jid_set(id,gid,JID_RESOURCE);
     users = xdb_get(mi->xc,id,NS_XGROUPS);

     if (group)
     {
         char *name;

         if (users == NULL)
         {
             users = xmlnode_new_tag("query");
             xmlnode_put_attrib(users,"xmlns",NS_XGROUPS);
         }

         name = xmlnode_get_tag_data(group,"name");
         if (name)
         {
             xmlnode_hide(xmlnode_get_tag(users,"name"));
             xmlnode_insert_cdata(xmlnode_insert_tag(users,"name"),name,-1);
         }

         /* check if the config marked this group as static */
         if (xmlnode_get_tag(group,"static"))
             xmlnode_insert_tag(users,"static");
     }

     return users;
}

void mod_groups_toplevel(xht h, const char *gid, void *val, void *arg)
{
    xmlnode result = (xmlnode) arg;
    xmlnode gc = (xmlnode) val;
    xmlnode group;
    pool p;

    p = xmlnode_pool(result);

    /* config overrides xdb */
    xmlnode_hide(xmlnode_get_tag(result,spools(p,"group?id=",gid,p)));

    group = xmlnode_insert_tag(result,"group");
    xmlnode_put_attrib(group,"name",xmlnode_get_tag_data(gc,"name"));
    xmlnode_put_attrib(group,"id",gid);
}

/* returns toplevel groups */
xmlnode mod_groups_get_top(mod_groups_i  mi, pool p, char *host)
{
    xmlnode result;

    result = xdb_get(mi->xc,jid_new(p,host),NS_XGROUPS);

    if (result == NULL)
        result = xmlnode_new_tag("query");

    log_debug("mod_groups","Inserting from config");

    /* insert toplevel groups from config */
    xhash_walk(mi->config,mod_groups_toplevel,(void *) result);

    return result;
}

void mod_groups_require(xht h, const char *gid, void *val, void *arg)
{
    xmlnode gc = (xmlnode) val;

    if (xmlnode_get_tag(gc,"require"))
    {
        xmlnode result = (xmlnode) arg;
        xmlnode group;
        pool p;

        log_debug("mod_groups","required group %s",gid);

        p = xmlnode_pool(result);
        group = xmlnode_get_tag(result,spools(p,"?id=",gid,p));

        if (group == NULL)
        {
            group = xmlnode_insert_tag(result,"group");
            xmlnode_put_attrib(group,"id",gid);

            /* remember the jid attrib is "?jid=<jid>" */
            if (xmlnode_get_tag(xmlnode_get_tag(gc,"users"),xmlnode_get_attrib(result,"jid")) != NULL)
                xmlnode_put_attrib(group,"subscription","both");
        }
        else
            xmlnode_put_attrib(group,"subscription","both");  
    }
}

xmlnode mod_groups_get_current(mod_groups_i mi, jid id)
{
    xmlnode result;
    pool p;

    id = jid_user(id);
    result = xdb_get(mi->xc,id,NS_XGROUPS);

    if (result == NULL)
        result = xmlnode_new_tag("query");

    p = xmlnode_pool(result);

    xmlnode_put_attrib(result,"jid",spools(p,"?jid=",jid_full(id),p));
    xhash_walk(mi->config,mod_groups_require,(void *) result);
    xmlnode_hide_attrib(result,"jid");

    return result;
}



void mod_groups_presence_to_walk(xht h, const char *key, void *val, void *arg)
{
    session from;

    from = js_session_primary((udata) val);

    if (from != NULL)
        js_session_to((session) arg,jpacket_new(xmlnode_dup(from->presence)));
}

void mod_groups_presence_to(session s, grouptab gt)
{
    udata u = s->u;
    jid id = s->u->id;

    if (xhash_get(gt->to,jid_full(id)) == NULL)
        xhash_put(gt->to,jid_full(id),u);

    xhash_walk(gt->from,mod_groups_presence_to_walk,(void *) s);
}

void mod_groups_presence_from_walk(xht h, const char *key, void *val, void *arg)
{
    xmlnode x = (xmlnode) arg;
    udata u = (udata) val;
    session s;

    s = xmlnode_get_vattrib(x,"s");
    if (s->u != u)
    {
        xmlnode pres;

        log_debug("mod_groups","delivering presence to %s",jid_full(u->id));

        pres = xmlnode_dup(x);
        xmlnode_put_attrib(pres,"to",jid_full(u->id));
        xmlnode_hide_attrib(pres,"s");
        js_session_from(s,jpacket_new(pres));
    }
}

void mod_groups_presence_from(session s, grouptab gt, xmlnode pres)
{
    udata u = s->u;

    log_debug("mod_groups","brodcasting");

    if (xhash_get(gt->from,jid_full(u->id)) == NULL)
        xhash_put(gt->from,jid_full(u->id),u);

    /* send our presence to online users subscribed to this group */
    xmlnode_hide_attrib(pres,"to");
    xmlnode_put_vattrib(pres,"s",s);
    xhash_walk(gt->to,mod_groups_presence_from_walk,(void *) pres);
    xmlnode_hide_attrib(pres,"s");
}

void mod_groups_roster_insert(udata u, xmlnode roster, xmlnode group, int add)
{
    xmlnode item, cur, q;
    char *id, *user, *name;

    user = jid_full(u->id);
    name = xmlnode_get_tag_data(group,"name");
    q = xmlnode_get_tag(roster,"query");

    /* loop through each item in the group */
    for (cur = xmlnode_get_firstchild(group); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        id = xmlnode_get_attrib(cur,"jid");
        if (id == NULL || strcmp(id,user) == 0)  /* don't push ourselves */
            continue;

        /* add them to the roster */
        item = xmlnode_insert_tag(q,"item");
        xmlnode_put_attrib(item,"jid",id);
        xmlnode_put_attrib(item,"subscription",add ? "to":"remove");
        xmlnode_put_attrib(item,"name",xmlnode_get_attrib(cur,"name"));

        xmlnode_insert_cdata(xmlnode_insert_tag(item,"group"),name,-1);
    }

    xmlnode_free(group);
}

void mod_groups_push(session s, xmlnode roster, int all)
{
    session cur;

    if (all)
    {
        /* send a copy to all session that have a roster */
        for(cur = s->u->sessions; cur != NULL; cur = cur->next)
            if(cur->roster)
                js_session_to(cur,jpacket_new(cur->next ? xmlnode_dup(roster):roster));
    }
    else
        js_session_to(s,jpacket_new(roster));
}

void mod_groups_update_walk(xht h, const char *key, void *val, void *arg)
{
    xmlnode packet = (xmlnode) arg;
    udata u = (udata) val;
    mod_groups_push(js_session_primary(u),xmlnode_dup(packet),1);
}

void mod_groups_update_group(grouptab gt, jid id, char *name, int add)
{
    xmlnode packet, item, q;

    packet = xmlnode_new_tag("iq");
    xmlnode_put_attrib(packet, "type", "set");
    q = xmlnode_insert_tag(packet, "query");
    xmlnode_put_attrib(q,"xmlns",NS_ROSTER);

    item = xmlnode_insert_tag(q,"item");
    xmlnode_put_attrib(item,"jid",jid_full(id));
    xmlnode_put_attrib(item,"subscription",add ? "to" : "remove");
    xmlnode_insert_cdata(xmlnode_insert_tag(item,"group"),name,-1);

    xhash_walk(gt->to,mod_groups_update_walk,(void *) packet);

    xmlnode_free(packet);
}



void mod_groups_register_get(mod_groups_i mi, mapi m)
{
    jpacket jp = m->packet;
    xmlnode q;

    if (strchr(jp->to->resource,'/') != NULL)  /* make sure it's somewhat valid */
    {
        jutil_iqresult(jp->x);
        q = xmlnode_insert_tag(jp->x,"query");
        xmlnode_put_attrib(q,"xmlns",NS_REGISTER);

        xmlnode_insert_cdata(xmlnode_insert_tag(q,"key"),jutil_regkey(NULL,jid_full(jp->from)),-1);
        xmlnode_insert_cdata(xmlnode_insert_tag(q,"instructions"),mi->inst,-1);
    }
    else
        jutil_error(jp->x,TERROR_NOTACCEPTABLE);

    jpacket_reset(jp);
    js_session_to(m->s,jp);
}

void mod_groups_register_set(mod_groups_i mi, mapi m)
{
    jpacket jp = m->packet;
    xmlnode groups, users, group, roster;
    udata u = m->user;
    pool p = jp->p;
    grouptab gt;
    char *gid, *host, *key;

    /* make sure it's a valid register query */
    key = xmlnode_get_tag_data(jp->iq,"key");
    gid = strchr(pstrdup(p,jp->to->resource),'/') + 1;
    if (gid == NULL || key == NULL || jutil_regkey(key,jid_full(jp->from)) == NULL)
    {
        jutil_error(jp->x,TERROR_NOTACCEPTABLE);
        jpacket_reset(jp);
        js_session_to(m->s,jp);
        return;
    }

    ++gid;
    host = u->id->server;

    log_debug("mod_groups","register GID %s",gid);

    /* get the groups the user is currently part of */
    groups = mod_groups_get_current(mi,u->id);
    if (groups == NULL)
    {
        groups = xmlnode_new_tag("query");
        xmlnode_put_attrib(groups,"xmlns",NS_XGROUPS);
    }

    group = xmlnode_get_tag(groups,spools(p,"?id=",gid,p));
    if (group == NULL)
    {
        group = xmlnode_insert_tag(groups,"group");
         xmlnode_put_attrib(group,"id",gid);
    }
    else if (j_strcmp(xmlnode_get_attrib(group,"subscription"),"both") == 0)
    {
        /* they are all ready registered */
        xmlnode_free(groups);
        jutil_iqresult(jp->x);
        jpacket_reset(jp);
        js_session_to(m->s,jp);
        return;
    }

    /* get the users from the new group */
    users = mod_groups_get(mi,p,host,gid);
    if (users == NULL)
    {
        xmlnode_free(groups);
        /* the group doesn't exist... allow users to create groups? */
        jutil_error(jp->x,TERROR_NOTFOUND);
        jpacket_reset(jp);
        js_session_to(m->s,jp);
        return;
    }

    gt = (grouptab) xhash_get(mi->groups,gid);
    if (gt == NULL)
    {
        log_debug("mod_groups","new group entry %s",gid);

        gt = pmalloco(u->si->p,sizeof(_grouptab));
        gt->to = xhash_new(509);
        gt->from = xhash_new(509);
        xhash_put(mi->groups,pstrdup(u->si->p,gid),gt);
    }

    if (xmlnode_get_tag(users,"static") == NULL)
    {
        if (xmlnode_get_tag(users,spools(p,"user?jid=",jid_full(u->id),p)) == NULL)
        {
            jid id;
            xmlnode user;

            id = jid_new(p,host);
            jid_set(id,gid,JID_RESOURCE);

            /* add the user to the group and save */
            user = xmlnode_insert_tag(users,"user");
            xmlnode_put_attrib(user,"jid",jid_full(u->id));
            xmlnode_put_attrib(user,"name",u->id->user);
            xdb_set(m->si->xc,id,NS_XGROUPS,users);

            /* push the new user */
            mod_groups_update_group(gt,u->id,xmlnode_get_tag_data(users,"name"),1);
        }

        xmlnode_put_attrib(group,"subscription","both");
        mod_groups_presence_from(m->s,gt,m->s->presence);
    }

    mod_groups_presence_to(m->s,gt);

    /* save the new group in the users list */
    if (xdb_set(m->si->xc,u->id,NS_XGROUPS,groups))
    {
        xmlnode_free(groups);
        xmlnode_free(users);

        jutil_error(jp->x,TERROR_UNAVAIL);
        jpacket_reset(jp);
        js_session_to(m->s,jp);
        return;
    }

    /* push the group to the user */
    roster = jutil_iqnew(JPACKET__SET,NS_ROSTER);
    mod_groups_roster_insert(u,roster,users,1);
    mod_groups_push(m->s,roster,1);

    jutil_iqresult(jp->x);
    jpacket_reset(jp);
    js_session_to(m->s,jp);
}

void mod_groups_browse_result(pool p, jpacket jp, xmlnode group, char *host)
{
    xmlnode q, cur, tag;
    char *name, *id;

    jutil_iqresult(jp->x);
    q = xmlnode_insert_tag(jp->x,"item");
    xmlnode_put_attrib(q,"xmlns",NS_BROWSE);
    xmlnode_put_attrib(q,"jid",jid_full(jp->to));

    name = xmlnode_get_tag_data(group,"name");
    xmlnode_put_attrib(q,"name",name ? name : "Toplevel groups");

    for (cur = xmlnode_get_firstchild(group); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        if (xmlnode_get_type(cur) != NTYPE_TAG) continue;

        name = xmlnode_get_name(cur);

        if (j_strcmp(name,"group") == 0)
        {
            tag = xmlnode_insert_tag(q,"item");
            xmlnode_put_attrib(tag,"name",xmlnode_get_attrib(cur,"name"));
            id = spools(p,host,"/groups/",xmlnode_get_attrib(cur,"id"),p);
            xmlnode_put_attrib(tag,"jid",id);
        }
        else if (j_strcmp(name,"user") == 0)
        {
            tag = xmlnode_insert_tag(q,"user");
            xmlnode_put_attrib(tag,"jid",xmlnode_get_attrib(cur,"jid")); 
            xmlnode_put_attrib(tag,"name",xmlnode_get_attrib(cur,"name"));
        }
    }
}

void mod_groups_browse_set(mod_groups_i mi, mapi m)
{
    jutil_error(m->packet->x,TERROR_NOTALLOWED);
    jpacket_reset(m->packet);
    js_deliver(m->si,m->packet);
}

void mod_groups_browse_get(mod_groups_i mi, mapi m)
{
    jpacket jp = m->packet;
    udata u = m->user;
    xmlnode group;
    pool p = jp->p;
    char *res, *host, *gid;

    log_debug("mod_groups","Browse request");

    host = u->id->server;
    res = pstrdup(p,jp->to->resource);

    gid = strchr(res,'/');
    if (gid != NULL)
    {
        *gid = '\0';  /* cur off leading "groups/" part of resource */
        ++gid;
        group = mod_groups_get(mi,p,host,gid);
    }
    else
    {
        group = mod_groups_get_top(mi,p,host);
        gid = NULL;
    }

    if (group)
    {
        mod_groups_browse_result(p,jp,group, host);
        xmlnode_free(group);
        jpacket_reset(jp);

        if (gid)
            xmlnode_insert_cdata(xmlnode_insert_tag(jp->iq,"ns"),NS_REGISTER,-1);
    }
    else
    {
        jutil_error(jp->x,TERROR_NOTFOUND);
        jpacket_reset(jp);
    }

    js_deliver(m->si,jp);
}

void mod_groups_roster(mod_groups_i mi, mapi m)
{
    udata u = m->user;
    xmlnode groups, users, cur, roster;
    pool p;
    char *host = u->id->server;

    /* get group the user is part of */
    if ((groups = mod_groups_get_current(mi,u->id)) == NULL)
        return;

    p = xmlnode_pool(groups);
    roster = jutil_iqnew(JPACKET__SET,NS_ROSTER);

    /* push each group */
    for (cur = xmlnode_get_firstchild(groups); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        if (xmlnode_get_type(cur) != NTYPE_TAG) continue;

        users = mod_groups_get(mi,p,host,xmlnode_get_attrib(cur,"id"));

        if (users != NULL)
            mod_groups_roster_insert(u,roster,users,1);
        else
            log_debug("mod_groups","Failed to get users for group");
    }

    mod_groups_push(m->s,roster,0);

    xmlnode_free(groups);
}

mreturn mod_groups_iq(mod_groups_i mi, mapi m)
{
    jid id;
    char *ns;
    int type;

    ns = xmlnode_get_attrib(m->packet->iq,"xmlns");
    if (ns == NULL) return M_PASS;

    id = m->packet->to;
    type = jpacket_subtype(m->packet);

    if (j_strcmp(ns,NS_ROSTER) == 0)
    {
        if (jpacket_subtype(m->packet) == JPACKET__GET)
        {
            log_debug("mod_groups","Roster request");
            mod_groups_roster(mi,m);
        }
    }
    else if (id->user == NULL && j_strncmp(id->resource,"groups",6) == 0)
    {
        if (strlen(id->resource) > 6 && id->resource[6] != '/')
            return M_PASS;

        if (j_strcmp(ns,NS_BROWSE) == 0)
        {
            if (type == JPACKET__GET)
                mod_groups_browse_get(mi,m);
            else
                mod_groups_browse_set(mi,m);
        }
        else if (j_strcmp(ns,NS_REGISTER) == 0)
        {
            log_debug("mod_groups","Register request");

            if (type == JPACKET__GET)
                mod_groups_register_get(mi,m);
            else if (type == JPACKET__SET)
                mod_groups_register_set(mi,m);
            else
                xmlnode_free(m->packet->x);
        }
        else
            xmlnode_free(m->packet->x);

        return M_HANDLED;
    }

    return M_PASS;
}



void mod_groups_presence(mod_groups_i mi, mapi m)
{
    grouptab gt;
    session s = m->s;
    udata u = m->user;
    xmlnode groups, cur;

    if ((groups = mod_groups_get_current(mi,u->id)) == NULL)
        return;

    log_debug("mod_groups","Getting groups for %s",jid_full(u->id));

    /* get each group */
    for (cur = xmlnode_get_firstchild(groups); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        char *gid;

        if ((gid = xmlnode_get_attrib(cur,"id")) == NULL) continue;

        gt = (grouptab) xhash_get(mi->groups,gid);
        if (gt == NULL)
        {
            log_debug("mod_groups","new group entry %s",gid);

            gt = pmalloco(u->si->p,sizeof(_grouptab));
            gt->to = xhash_new(509);
            gt->from = xhash_new(509);
            xhash_put(mi->groups,pstrdup(u->si->p,gid),gt);
        }

        if(j_strcmp(xmlnode_get_attrib(cur,"subscription"),"both") == 0)
            mod_groups_presence_from(s,gt,m->packet->x);

        /* if we are new or our old priority was less then zero then probe the users */
        if (js_session_primary(m->user) == NULL || m->s->priority < 0)
            mod_groups_presence_to(s,gt);
    }

    xmlnode_free(groups);
}

mreturn mod_groups_out(mapi m, void *arg)
{
    mod_groups_i mi = (mod_groups_i) arg;

    if (m->packet->type == JPACKET_PRESENCE)
    {
        if (m->packet->to == NULL) mod_groups_presence(mi,m);
        return M_PASS;
    }
    else if (m->packet->type == JPACKET_IQ)
        return mod_groups_iq(mi,m);

    return M_IGNORE;
}

mreturn mod_groups_end(mapi m, void *arg)
{
    mod_groups_i mi = (mod_groups_i) arg;
    xmlnode groups, cur;
    udata u = m->user;
    jid id = u->id;
    grouptab gt;

    if (js_session_primary(u) != NULL || (groups = mod_groups_get_current(mi,id)) == NULL)
        return M_PASS;

    log_debug("mod_groups","removing user from table");
    for (cur = xmlnode_get_firstchild(groups); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        gt = (grouptab) xhash_get(mi->groups,xmlnode_get_attrib(cur,"id"));
        if (gt == NULL) continue;

        if(j_strcmp(xmlnode_get_attrib(cur,"subscription"),"both") == 0)
            xhash_zap(gt->from,jid_full(id));

        xhash_zap(gt->to,jid_full(id));
    }

    xmlnode_free(groups);

    return M_PASS;
}

mreturn mod_groups_session(mapi m, void *arg)
{
    js_mapi_session(es_OUT,m->s,mod_groups_out,arg);
    js_mapi_session(es_END,m->s,mod_groups_end,arg);
    return M_PASS;
}

/* messages to groups */
void mod_groups_message_walk(xht h, const char *key, void *val, void *arg)
{
    xmlnode m = (xmlnode) arg;
    udata u = (udata) val;

    m = xmlnode_dup(m);
    xmlnode_put_attrib(m,"to",jid_full(u->id));
    js_deliver(u->si,jpacket_new(m));
}

mreturn mod_groups_message(mapi m, void *arg)
{
    mod_groups_i mi = (mod_groups_i) arg;
    grouptab gt;
    jpacket jp = m->packet;
    jid id = jp->to;
    char *gid;

    if(jp->type != JPACKET_MESSAGE) return M_IGNORE;
    if(j_strncmp(id->resource,"groups/",7) != 0) return M_PASS;

    /* circular safety */
    if(xmlnode_get_tag(jp->x,"x?xmlns=" NS_DELAY) != NULL)
    {
        xmlnode_free(jp->x);
        return M_HANDLED;
    }

    gid = strchr(id->resource,'/') + 1;
    if (gid == NULL)
    {
        jutil_error(jp->x,TERROR_NOTALLOWED);
        jpacket_reset(jp);
        js_deliver(m->si,jp);
        return M_HANDLED;
    }

    gt = (grouptab) xhash_get(mi->groups,gid);
    if (gt)
    {
        xmlnode cfg;

        cfg = xhash_get(mi->config,gid);
        if (cfg && xmlnode_get_tag(cfg,spools(jp->p,"write/user=",jp->from->user,jp->p)) != NULL)
        {
            log_debug("mod_groups","broadcast message to '%s'",gid);

            xmlnode_put_attrib(jp->x,"from",xmlnode_get_attrib(jp->x,"to"));
            xmlnode_hide_attrib(jp->x,"to");
            xhash_walk(gt->from,mod_groups_message_walk,(void *) jp->x);
            xmlnode_free(jp->x);
        }
        else
        {
            jutil_error(jp->x,TERROR_NOTALLOWED);
            jpacket_reset(jp);
            js_deliver(m->si,jp);
        }
    }
    else
    {
        jutil_error(jp->x,TERROR_NOTFOUND);
        jpacket_reset(jp);
        js_deliver(m->si,jp);
    }

    return M_HANDLED;
}

void mod_groups_destroy(xht h, const char *key, void *val, void *arg)
{
    grouptab gt = (grouptab) val;

    xhash_free(gt->to);
    xhash_free(gt->from);
}

mreturn mod_groups_shutdown(mapi m, void *arg)
{
    mod_groups_i mi = (mod_groups_i) arg;

    xhash_walk(mi->groups,mod_groups_destroy,NULL);
    xhash_free(mi->groups);
    xhash_free(mi->config);

    return M_PASS;
}

/* init */
void mod_groups(jsmi si)
{
    mod_groups_i mi;
    xmlnode cur, config;
    char *gid;

    log_debug("mod_groups","initing");

    config = js_config(si,"groups");
    mi = pmalloco(si->p,sizeof(_mod_groups_i));

    if (config != NULL)
    {
        mi->config = xhash_new(67);
        for (cur = xmlnode_get_firstchild(config); cur != NULL; cur = xmlnode_get_nextsibling(cur))
        {
            if (j_strcmp(xmlnode_get_name(cur),"group") != 0) continue;
            gid = xmlnode_get_attrib(cur,"id");
            if (gid == NULL)
            {
                log_error("sessions","mod_groups: Error loading, no id attribute on group");
                return;
            }
            else if (strchr(gid,'/') != NULL)
            {
                log_error("sessions","mod_groups: Error loading, sub-groups not allowed in config");
                return;
            }

            xhash_put(mi->config,pstrdup(si->p,gid),cur);
        }
    }

    mi->groups = xhash_new(67);
    mi->xc = si->xc;
    mi->inst = xmlnode_get_tag_data(config,"instructions");
    if (mi->inst == NULL)
        mi->inst = pstrdup(si->p,"This will add a group to your roster");

    js_mapi_register(si,e_SERVER,mod_groups_message,(void *) mi);
    js_mapi_register(si,e_SESSION,mod_groups_session,(void *) mi);
    js_mapi_register(si,e_SHUTDOWN,mod_groups_shutdown,(void *) mi);
}
