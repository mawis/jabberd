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

#define NS_BROWSE "jabber:iq:browse"
#define NS_XGROUPS "jabber:xdb:groups"

typedef struct
{
    xdbcache xc;
    HASHTABLE groups;
    HASHTABLE config; /* hash of group specfic config */
} *mod_groups_i, _mod_groups_i;

typedef struct
{
    HASHTABLE to;
    HASHTABLE from;
} *grouptab, _grouptab;

xmlnode mod_groups_get(mod_groups_i mi, pool p, char *host, char *gid)
{
     xmlnode group, users;

     if (gid == NULL) return NULL;

     log_debug("mod_groups","checking config");

     /* check config for specfic group before xdb */
     group = (xmlnode) ghash_get(mi->config,gid);

     if (group != NULL)
     {
         users = xmlnode_get_tag(group,"users");
         if (users)
         {
             users = xmlnode_dup(users);
             xmlnode_insert_cdata(xmlnode_insert_tag(users,"name"),xmlnode_get_tag_data(group,"name"),-1);
             return users;
         }
     }

     return xdb_get(mi->xc,jid_new(p,host),spools(p,"jabber:xdb:groups/",gid,p));
}

int _mod_groups_toplevel(void *arg, const void *gid, void *data)
{
    xmlnode result = (xmlnode) arg;
    xmlnode gc = (xmlnode) data;
    xmlnode group;
    pool p;

    p = xmlnode_pool(result);

    /* config overrides xdb */
    xmlnode_hide(xmlnode_get_tag(result,spools(p,"group?id=",gid,p)));

    group = xmlnode_insert_tag(result,"group");
    xmlnode_put_attrib(group,"name",xmlnode_get_tag_data(gc,"name"));
    xmlnode_put_attrib(group,"id",gid);

    return 1;
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
    ghash_walk(mi->config,_mod_groups_toplevel,(void *) result);

    return result;
}

int _mod_groups_require(void *arg, const void *gid, void *data)
{
    xmlnode result = (xmlnode) arg;
    xmlnode gc = (xmlnode) data;
    xmlnode group;
    pool p;

    if (xmlnode_get_tag(gc,"require") == NULL) return 1;

    log_debug("mod_groups","required group %s",gid);

    p = xmlnode_pool(result);
    group = xmlnode_get_tag(result,spools(p,"?id=",gid,p));

    if (group == NULL)
    {
        group = xmlnode_insert_tag(result,"group");
        xmlnode_put_attrib(group,"id",gid);
    }

    if (xmlnode_get_tag(xmlnode_get_tag(gc,"users"),xmlnode_get_attrib(result,"jid")) != NULL)
        xmlnode_put_attrib(group,"subscription","both");

    xmlnode_put_attrib(group,"name",xmlnode_get_tag_data(gc,"name"));

    return 1;
}

xmlnode mod_groups_get_current(mod_groups_i mi, jid id)
{
    xmlnode result;
    pool p;

    result = xdb_get(mi->xc,jid_user(id),NS_XGROUPS);
    
    if (result == NULL)
        result = xmlnode_new_tag("query");

    p = xmlnode_pool(result);

    xmlnode_put_attrib(result,"jid",spools(p,"?jid=",jid_full(id),p));
    ghash_walk(mi->config,_mod_groups_require,(void *) result);
    xmlnode_hide_attrib(result,"jid");

    return result;
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

void mod_groups_roster_add(udata u, xmlnode roster, xmlnode group, int add)
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
        xmlnode_insert_cdata(xmlnode_insert_tag(q,"instructions"),"This will add a group to your roster",-1);
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
    pool p;
    char *gid, *host, *key;

    p = xmlnode_pool(jp->x);

    /* make sure it's a valid register query */
    key = xmlnode_get_tag_data(jp->iq,"key");
    gid = strchr(pstrdup(p,jp->to->resource),'/');
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

    /* get the current groups the user is part of */
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

        /* xmlnode_put_attrib(group,"name",name); */
    }
    else if (j_strcmp(xmlnode_get_attrib(group,"subscription"),"both") == 0)
        return;

    if (/* inclusive/not static */0)
    {
        /* XXX change and save group */
        xmlnode_put_attrib(group,"subscription","both");
    }

    /* save the new group in the users list */
    if (xdb_set(m->si->xc,u->id,NS_XGROUPS,groups))
    {
        xmlnode_free(groups);
        jutil_error(jp->x,TERROR_UNAVAIL);
        jpacket_reset(jp);
        js_session_to(m->s,jp);
        return;
    }

    /* get the users from the new group */
    users = mod_groups_get(mi,p,host,gid);
    if (users == NULL)
    {
        /* odd, who knows? */
        jutil_error(jp->x,TERROR_INTERNAL);
        jpacket_reset(jp);
        js_session_to(m->s,jp);
        return;
    }

    /* push the new group */
    roster = jutil_iqnew(JPACKET__SET,NS_ROSTER);
    mod_groups_roster_add(u,roster,users,1);
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
    q = xmlnode_insert_tag(jp->x,"query");
    xmlnode_put_attrib(q,"xmlns",NS_XGROUPS);

    for (cur = xmlnode_get_firstchild(group); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        if (xmlnode_get_type(cur) != NTYPE_TAG) continue;

        name = xmlnode_get_name(cur);

        if (j_strcmp(name,"group") == 0)
        {
            tag = xmlnode_insert_tag(q,"folder");
            xmlnode_put_attrib(tag,"name",xmlnode_get_attrib(cur,"name"));
            id = spools(p,host,"/groups/",xmlnode_get_attrib(cur,"id"),p);
            xmlnode_put_attrib(tag,"jid",id);
        }
        else if (j_strcmp(name,"user") == 0)
        {
            tag = xmlnode_insert_tag(q,"user");
            xmlnode_put_attrib(tag,"jid",xmlnode_get_attrib(cur,"jid"));
        }
    }
}

void mod_groups_browse(mod_groups_i mi, mapi m)
{
    jpacket jp = m->packet;
    udata u = m->user;
    xmlnode group;
    pool p;
    char *res, *host, *gid;

    p = xmlnode_pool(jp->x);
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
        {
            /* XXX if allowed to register? */
            xmlnode_insert_cdata(xmlnode_insert_tag(jp->iq,"ns"),NS_REGISTER,-1);
        }
    }
    else
    {
        jutil_error(jp->x,TERROR_NOTFOUND);
        jpacket_reset(jp);
    }

    js_deliver(m->si,jp);
}

void mod_groups_roster_push(mod_groups_i mi, mapi m)
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
            mod_groups_roster_add(u,roster,users,1);
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
            mod_groups_roster_push(mi,m);
        }
    }
    else if (id && id->user == NULL && (j_strlen(id->resource) >= 6) &&
             strncmp(id->resource,"groups",6) == 0)
    {
        if (j_strcmp(ns,NS_BROWSE) == 0)
        {
            if (type == JPACKET__GET)
            {
                log_debug("mod_groups","Browse request");
                mod_groups_browse(mi,m);
            }
            else
                xmlnode_free(m->packet->x);
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

void mod_groups_presence_to(grouptab gt, xmlnode users, session s, pool p, char *gid, int new)
{
    udata u = s->u;
    xmlnode cur, pres;
    jid uid = s->u->id, id;
    session from;

    for (cur = xmlnode_get_firstchild(users); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        if ((id = jid_new(p,xmlnode_get_attrib(cur,"jid"))) == NULL) continue;

        if (new == 0)
        {
            log_debug("mod_groups","getting presence from cache");

            /* get the users presence from the cache */
            while((pres = ppdb_get(u->p_cache,id)) != NULL)
                js_session_to(s,jpacket_new(xmlnode_dup(pres)));
        }
        else
        {
            log_debug("mod_groups","probing user %s",jid_full(id));

            if (ghash_get(gt->to,jid_full(uid)) == NULL)
                ghash_put(gt->to,jid_full(uid),u);

            from = js_session_primary((udata) ghash_get(gt->from,jid_full(id)));

            if (from != NULL)
                js_session_to(s,jpacket_new(xmlnode_dup(from->presence)));
        }
    }

    xmlnode_free(users);
}

int _mod_groups_preswalk(void *arg, const void *key, void *data)
{
    xmlnode p = (xmlnode) arg, pres;
    udata u = (udata) data;
    session s;

    s = xmlnode_get_vattrib(p,"s");

    if (s->u != u)
    {
        log_debug("mod_groups","delivering presence to %s",jid_full(u->id));

        pres = xmlnode_dup(p);
        xmlnode_put_attrib(pres,"to",jid_full(u->id));
        xmlnode_hide_attrib(pres,"s");
        js_session_from(s,jpacket_new(pres));
    }

    return 1;
}

void mod_groups_presence(mod_groups_i mi, mapi m)
{
    grouptab gt;
    session s;
    udata u = m->user;
    xmlnode groups, cur, users;
    pool p;
    char *gid;
    int probe;

    if ((groups = mod_groups_get_current(mi,u->id)) == NULL)
        return;

    s = js_session_primary(m->user);
    /* if we are new or our old priority was less then zero then probe the users */
    probe = (s == NULL || m->s->priority < 0) ? 1 : 0;
    p = xmlnode_pool(groups);

    log_debug("mod_groups","Getting groups for %s, probe %d",jid_full(u->id),probe);

    /* get each group */
    for (cur = xmlnode_get_firstchild(groups); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        if ((gid = xmlnode_get_attrib(cur,"id")) == NULL) continue;

        gt = (grouptab) ghash_get(mi->groups,gid);
        if (gt == NULL)
        {
            log_debug("mod_groups","new group entry %s",gid);

            gt = pmalloco(u->si->p,sizeof(_grouptab));
            gt->to = ghash_create(509,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
            gt->from = ghash_create(509,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
            ghash_put(mi->groups,pstrdup(u->si->p,gid),gt);
        }

        if(j_strcmp(xmlnode_get_attrib(cur,"subscription"),"both") == 0)
        {
            log_debug("mod_groups","brodcasting");

            /* send our presence to online users subscribed to this group */
            xmlnode_hide_attrib(m->packet->x,"to");
            xmlnode_put_vattrib(m->packet->x,"s",m->s);
            ghash_walk(gt->to,_mod_groups_preswalk,(void *) m->packet->x);
            xmlnode_hide_attrib(m->packet->x,"s");

            if (ghash_get(gt->from,jid_full(u->id)) == NULL)
                ghash_put(gt->from,jid_full(u->id),u);
        }

        if (probe && (users = mod_groups_get(mi,p,u->id->server,gid)) != NULL)
            mod_groups_presence_to(gt,users,m->s,p,gid,s == NULL);
    }

    xmlnode_free(groups);
}

mreturn mod_groups_out(mapi m, void *arg)
{
    mod_groups_i mi = (mod_groups_i) arg;

    if (m->packet->type == JPACKET_PRESENCE)
    {
        if (m->packet->to == NULL)
            mod_groups_presence(mi,m);
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
        gt = (grouptab) ghash_get(mi->groups,xmlnode_get_attrib(cur,"id"));
        if (gt == NULL) continue;

        if(j_strcmp(xmlnode_get_attrib(cur,"subscription"),"both") == 0)
            ghash_remove(gt->from,jid_full(id));

        ghash_remove(gt->to,jid_full(id));
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

int mod_groups_destroy(void *arg, const void *key, void *data)
{
    grouptab gt = (grouptab) data;

    ghash_destroy(gt->to);
    ghash_destroy(gt->from);

    return 1;
}

mreturn mod_groups_shutdown(mapi m, void *arg)
{
    mod_groups_i mi = (mod_groups_i) arg;

    ghash_walk(mi->groups, mod_groups_destroy,NULL);
    ghash_destroy(mi->groups);

    ghash_destroy(mi->config);

    return M_PASS;
}

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
        mi->config = ghash_create(67,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
        for (cur = xmlnode_get_firstchild(config); cur != NULL; cur = xmlnode_get_nextsibling(cur))
        {
            if (j_strcmp(xmlnode_get_name(cur),"group") != 0) continue;
            gid = xmlnode_get_attrib(cur,"id");
            if (gid == NULL)
            {
                log_error("sessions","Error loading shared group config");
                return;
            }

            ghash_put(mi->config,pstrdup(si->p,gid),cur);
        }
    }

    mi->groups = ghash_create(67,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);
    mi->xc = si->xc;

    js_mapi_register(si,e_SESSION,mod_groups_session,(void *) mi);
    js_mapi_register(si,e_SHUTDOWN,mod_groups_shutdown,(void *) mi);
}
