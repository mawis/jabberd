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
 * Portions Copyright (c) 1998-1999 Schuyler Heath.
 *                    (c) 2001      Philip Anderson.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * --------------------------------------------------------------------------*/
#include "jsm.h"

/**
 * @file mod_groups.c
 * @brief handle roster groups (optional module, not enabled by default)
 */

#define NS_XGROUPS "jabber:xdb:groups"		/**< namespace to store groups in xdb */
#define NS_XINFO   "jabber:xdb:groups:info"	/**< info about the group, name, edit/write perms, etc... */

/**
 * get a grouptab from the mi->groups hash or add a new one if it does not already exist
 */
#define GROUP_GET(mi,gid) (gt = (grouptab) xhash_get(mi->groups,gid)) ? gt : mod_groups_tab_add(mi,gid)

/** module configuration */
typedef struct {
    pool p;		/**< used memory pool */
    xdbcache xc;	/**< xdbcache used for xdb queries */
    xht groups;
    xht config;		/**< hash of group specfic config: contains xmlnode instances */
    char *inst;		/**< register instructions */
} *mod_groups_i, _mod_groups_i;

/** data for a single group */
typedef struct {
    xht to;
    xht from;
} *grouptab, _grouptab;

/**
 * get the information/configuration of a group
 *
 * @param mi the module internal data
 * @param p memory pool to use for processing
 * @param host server hostname of this group
 * @param gid group ID
 * @return information xmlnode, either from xdb or the static configuration (prefered)
 */
xmlnode mod_groups_get_info(mod_groups_i mi, pool p, char *host, char *gid) {
    xmlnode info, xinfo, cur;
    jid id;

    if (gid == NULL) return NULL;

    log_debug2(ZONE, LOGT_DELIVER, "Getting info %s",gid);

    id = jid_new(p,host);
    jid_set(id,gid,JID_RESOURCE);
    xinfo = xdb_get(mi->xc,id,NS_XINFO);

    info = xmlnode_get_tag((xmlnode) xhash_get(mi->config,gid),"info");
    if (info != NULL)
        info = xmlnode_dup(info);
    else
        return xinfo;

    for (cur = xmlnode_get_firstchild(xinfo); cur != NULL; cur = xmlnode_get_nextsibling(cur))
        if (xmlnode_get_tag(info,xmlnode_get_name(cur)) == NULL) /* config overrides */
            xmlnode_insert_node(info,cur);

    xmlnode_free(xinfo);

    return info;
}

/**
 * get the users that are member of a group
 *
 * @param mi the mod_groups_i struct containing module instance data
 * @param p the memory pool to use
 * @param host the host of the group
 * @param gid the group id for which to get the users
 * @return xmlnode containing the users
 */
xmlnode mod_groups_get_users(mod_groups_i mi, pool p, char *host, char *gid) {
    xmlnode group, users;
    jid id;

    if (gid == NULL) return NULL;

    log_debug2(ZONE, LOGT_DELIVER, "getting users %s",gid);

    /* check config for specfic group before xdb */
    group = (xmlnode) xhash_get(mi->config,gid);

    if (group != NULL && (users = xmlnode_get_tag(group,"users")) != NULL)
        return xmlnode_dup(users);

    log_debug2(ZONE, LOGT_DELIVER, "%d %d",group != NULL,users!= NULL);

    id = jid_new(p,host);
    jid_set(id,gid,JID_RESOURCE);

    return xdb_get(mi->xc,id,NS_XGROUPS);
}

/**
 * xhash_walker() function used by mod_groups_get_top() to iterate over the groups
 *
 * @param h xht that contains the groups (unused/ignored)
 * @param gid the group id
 * @param val the group definition
 * @param arg xmlnode where to store the result
 */
void mod_groups_top_walk(xht h, const char *gid, void *val, void *arg) {
    if (strchr(gid,'/') == NULL) {
        xmlnode result = (xmlnode) arg;
        xmlnode group, info;
        pool p;

        p = xmlnode_pool(result);

        /* config overrides xdb */
        xmlnode_hide(xmlnode_get_tag(result,spools(p,"group?id=",gid,p)));

        /* bah, vattrib hack */
        info = mod_groups_get_info((mod_groups_i) xmlnode_get_vattrib(result,"mi"),p,xmlnode_get_attrib(result,"host"),(char *) gid);

        group = xmlnode_insert_tag(result,"group");
        xmlnode_put_attrib(group,"name",xmlnode_get_tag_data(info,"name"));
        xmlnode_put_attrib(group,"id",gid);

        xmlnode_free(info);
    }
}

/**
 * returns toplevel groups
 *
 * @param mi the mod_groups_i struct containing module instance data
 * @param p the memory pool to use
 * @param host the host for which the result is generated
 * @return list of the toplevel groups
 */
xmlnode mod_groups_get_top(mod_groups_i  mi, pool p, char *host) {
    xmlnode result;

    result = xdb_get(mi->xc,jid_new(p,host),NS_XGROUPS);

    if (result == NULL)
        result = xmlnode_new_tag("query");

    xmlnode_put_vattrib(result,"mi",(void *) mi);
    xmlnode_put_attrib(result,"host",host);

    /* insert toplevel groups from config */
    xhash_walk(mi->config,mod_groups_top_walk,(void *) result);

    xmlnode_hide_attrib(result,"mi");
    xmlnode_hide_attrib(result,"host");

    return result;
}

/**
 * inserts required groups into result
 *
 * xhash_walker() function used by mod_groups_get_current() to iterate over the groups
 *
 * @param h the xht containing the groups
 * @param gid the group id
 * @param val the group definition (xmlnode)
 * @param arg xmlnode where to put the result to
 */
void mod_groups_current_walk(xht h, const char *gid, void *val, void *arg) {
    xmlnode info;

    info = xmlnode_get_tag((xmlnode) val,"info");

    if (xmlnode_get_tag(info,"require") != NULL) {
        xmlnode result = (xmlnode) arg;
        xmlnode group;
        pool p;

        log_debug2(ZONE, LOGT_DELIVER, "required group %s",gid);

        p = xmlnode_pool(result);
        group = xmlnode_get_tag(result,spools(p,"?id=",gid,p));

        if (group == NULL) {
            group = xmlnode_insert_tag(result,"group");
            xmlnode_put_attrib(group,"id",gid);

            /* remember the jid attrib is "?jid=<jid>" */
            if (xmlnode_get_tag(xmlnode_get_tag(info,"users"),xmlnode_get_attrib(result,"jid")) != NULL)
                xmlnode_put_attrib(group,"type","both");
        } else {
            xmlnode_put_attrib(group,"type","both");  
	}
    }
}

/**
 * get the list of groups a user is currently a member of
 *
 * @param mi the mod_groups_i struct containing the module instance data
 * @param id for which user to get the list of groups
 * @return list of groups
 */
xmlnode mod_groups_get_current(mod_groups_i mi, jid id) {
    xmlnode result;
    pool p;

    id = jid_user(id);
    result = xdb_get(mi->xc,id,NS_XGROUPS);

    if (result == NULL)
        result = xmlnode_new_tag("query");

    p = xmlnode_pool(result);

    xmlnode_put_attrib(result,"jid",spools(p,"?jid=",jid_full(id),p));
    xhash_walk(mi->config,mod_groups_current_walk,(void *) result);
    xmlnode_hide_attrib(result,"jid");

    return result;
}

/**
 * create a new grouptab entry and add to the groups hash
 *
 * @param mi the mod_groups_i struct containing module instance data
 * @param gid the group id
 * @return the newly created grouptab entry
 */
grouptab mod_groups_tab_add(mod_groups_i mi, char *gid) {
    grouptab gt;

    log_debug2(ZONE, LOGT_DELIVER, "new group entry %s",gid);
    gt = pmalloco(mi->p,sizeof(_grouptab));
    gt->to = xhash_new(509);
    gt->from = xhash_new(509);
    xhash_put(mi->groups,pstrdup(mi->p,gid),gt);

    return gt;
}

/**
 * xhash_walker() function used by mod_groups_presence_to() to iterate over the users
 *
 * @param h the xht that contains the users (unused/ignored)
 * @param kay the user (unused/ignored)
 * @param val the udata struct of the user
 * @param arg the session for which to send the presence
 */
void mod_groups_presence_to_walk(xht h, const char *key, void *val, void *arg) {
    session from;

    from = js_session_primary((udata) val);

    if (from != NULL)
        js_session_to((session) arg,jpacket_new(xmlnode_dup(from->presence)));
}

/**
 * send presence to a session from the group members
 *
 * @param s the session for which to send the presence
 * @param gt the grouptab to which users the presence should be sent
 */
void mod_groups_presence_to(session s, grouptab gt) {
    xhash_put(gt->to,jid_full(s->u->id),(void *) s->u); /* we don't care if it replaces the old entry */
    xhash_walk(gt->from,mod_groups_presence_to_walk,(void *) s);
}

/**
 * xhash_walker() function used by mod_groups_presence_from() to iterate over all users
 *
 * @param h the xht containing the users (unused/ignored)
 * @param key the user (unused/ignored)
 * @param val the udata struct of the user
 * @param arg the presence to send
 */
void mod_groups_presence_from_walk(xht h, const char *key, void *val, void *arg) {
    xmlnode x = (xmlnode) arg;
    udata u = (udata) val;
    session s;

    s = xmlnode_get_vattrib(x,"s");
    if (s->u != u) {
        xmlnode pres;

        log_debug2(ZONE, LOGT_DELIVER, "delivering presence to %s",jid_full(u->id));

        pres = xmlnode_dup(x);
        xmlnode_put_attrib(pres,"to",jid_full(u->id));
        xmlnode_hide_attrib(pres,"s");
        js_session_from(s,jpacket_new(pres));
    }
}

/**
 * send presence from a session to online members of a group
 *
 * @param s which sessions presence should be sent
 * @param gt the grouptab for this group
 * @param pres the presence to send
 */
void mod_groups_presence_from(session s, grouptab gt, xmlnode pres) {
    udata u = s->u;

    log_debug2(ZONE, LOGT_DELIVER, "brodcasting");

    if (xhash_get(gt->from,jid_full(u->id)) == NULL)
        xhash_put(gt->from,jid_full(u->id),u);

    /* send our presence to online users subscribed to this group */
    xmlnode_hide_attrib(pres,"to");
    xmlnode_put_vattrib(pres,"s",s);
    xhash_walk(gt->to,mod_groups_presence_from_walk,(void *) pres);
    xmlnode_hide_attrib(pres,"s");
}

/**
 * insert the users of a group as items to the roster xmlnode
 *
 * @param u the user for which the roster is created (which roster item to leave out)
 * @param roster where to add the items to
 * @param group which group's members should be added
 * @param gn the group name
 * @param add add items or remove them
 */
void mod_groups_roster_insert(udata u, xmlnode roster, xmlnode group, char *gn, int add) {
    xmlnode item, cur, q;
    char *id, *user;

    user = jid_full(u->id);
    q = xmlnode_get_tag(roster,"query");

    /* loop through each item in the group */
    for (cur = xmlnode_get_firstchild(group); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
        id = xmlnode_get_attrib(cur,"jid");
        if (id == NULL || strcmp(id,user) == 0)  /* don't push ourselves */
            continue;

        /* add them to the roster */
        item = xmlnode_insert_tag(q,"item");
        xmlnode_put_attrib(item,"jid",id);
        xmlnode_put_attrib(item,"subscription",add ? "to":"remove");
        xmlnode_put_attrib(item,"name",xmlnode_get_attrib(cur,"name"));

        xmlnode_insert_cdata(xmlnode_insert_tag(item,"group"),gn,-1);
    }

    xmlnode_free(group);
}

/**
 * push updated roster to all sessions or a specfic session
 *
 * @param s one session of the user
 * @param roster the roster to be pushed
 * @param all if 0 the roster is pushed only to the given session, else it is pushed to all sessions of the user
 */
void mod_groups_roster_push(session s, xmlnode roster, int all) {
    session cur;

    if (all) {
        /* send a copy to all session that have a roster */
        for(cur = s->u->sessions; cur != NULL; cur = cur->next)
            if(cur->roster)
                js_session_to(cur,jpacket_new(cur->next ? xmlnode_dup(roster):roster));
    } else {
        js_session_to(s,jpacket_new(roster));
    }
}

/**
 * xhash_walker() function used by mod_groups_update_roster() to iterate over all users of a group
 *
 * @param h the xht containing the users (unused/ignored)
 * @param key the user (unused/ignored)
 * @param val the udata struct of the user
 * @param arg the packet to send
 */
void mod_groups_update_walk(xht h, const char *key, void *val, void *arg) {
    xmlnode packet = (xmlnode) arg;
    udata u = (udata) val;
    mod_groups_roster_push(js_session_primary(u),xmlnode_dup(packet),1);
}

/**
 * updates every members roster with the new user
 *
 * @param gt grouptab struct for the relevant group
 * @param uid the new user
 * @param un the user's name
 * @param gn the group's name
 * @param add if the user is added or removed
 */
void mod_groups_update_rosters(grouptab gt, jid uid, char *un, char *gn, int add) {
    xmlnode packet, item, q;

    packet = xmlnode_new_tag("iq");
    xmlnode_put_attrib(packet, "type", "set");
    q = xmlnode_insert_tag(packet, "query");
    xmlnode_put_attrib(q,"xmlns",NS_ROSTER);

    item = xmlnode_insert_tag(q,"item");
    xmlnode_put_attrib(item,"jid",jid_full(uid));
    xmlnode_put_attrib(item,"name",un);
    xmlnode_put_attrib(item,"subscription",add ? "to" : "remove");
    xmlnode_insert_cdata(xmlnode_insert_tag(item,"group"),gn,-1);

    xhash_walk(gt->to,mod_groups_update_walk,(void *) packet);

    xmlnode_free(packet);
}

/**
 * adds a user to the master group list and to their personal list
 *
 * @param mi mod_groups_i struct containing module instance data
 * @param p memory pool to use
 * @param uid the user, that should be added
 * @param un the user's name
 * @param gid the group id to add the user to
 * @param gn the group name
 * @param both subscription type both?
 * @return 1 on failure, 0 on success
 */
int mod_groups_xdb_add(mod_groups_i mi, pool p, jid uid, char *un, char *gid, char *gn, int both) {
    xmlnode groups, user, group;
    jid xid;

    xid = jid_new(p,uid->server);
    jid_set(xid,gid,JID_RESOURCE);

    user = xmlnode_new_tag("user");
    xmlnode_put_attrib(user,"jid",jid_full(uid));
    xmlnode_put_attrib(user,"name",un);

    if(both && xdb_act(mi->xc,xid,NS_XGROUPS,"insert",spools(p,"?jid=",jid_full(uid),p),user)) {
        log_debug2(ZONE, LOGT_DELIVER, "Failed to insert user");
        xmlnode_free(user);
        return 1;
    }
    xmlnode_free(user);

    /* get the groups this user is currently part of */
    groups = mod_groups_get_current(mi,uid);
    if (groups == NULL) {
        groups = xmlnode_new_tag("query");
        xmlnode_put_attrib(groups,"xmlns",NS_XGROUPS);
    }

    /* check if the user already as the group listed */
    group = xmlnode_get_tag(groups,spools(p,"?id=",gid,p));
    if (group == NULL) {
        group = xmlnode_insert_tag(groups,"group");
        xmlnode_put_attrib(group,"id",gid);
    } else if (j_strcmp(xmlnode_get_attrib(group,"type"),"both") == 0 && both) {
        /* the group is already there */
        xmlnode_free(groups);
        return 0;
    } else if (both == 0) {
        xmlnode_free(groups);
        return 0;
    }

    /* save the new group in the users list groups */
    if (both)
        xmlnode_put_attrib(group,"type","both");

    xdb_set(mi->xc,uid,NS_XGROUPS,groups);
    xmlnode_free(groups);

    return 0;
}

/**
 * removes a user from the master group list and from their personal list
 *
 * @param mi the mod_groups_i struct containing module instance data
 * @param p memory pool to use
 * @param uid which user to remove
 * @param host host to use
 * @param gid group id from which the user should be removed
 * @return 0 on success, 1 on failure
 */
int mod_groups_xdb_remove(mod_groups_i mi, pool p, jid uid, char *host, char *gid) {
    xmlnode groups, group, info;
    jid xid;

    xid = jid_new(p,uid->server);
    jid_set(xid,gid,JID_RESOURCE);

    /* insert with a match will overwrite the node with NULL and therefore remove it */
    if(xdb_act(mi->xc,xid,NS_XGROUPS,"insert",spools(p,"?jid=",jid_full(uid),p),NULL)) {
        log_debug2(ZONE, LOGT_DELIVER, "Failed to remove user");
        return 1;
    }

    info = mod_groups_get_info(mi, p, host, gid);
    if (xmlnode_get_tag(info,"require") != NULL)
        return 0;

    /* get the groups this user is currently part of */
    groups = mod_groups_get_current(mi,uid);
    if (groups == NULL) {
        groups = xmlnode_new_tag("query");
        xmlnode_put_attrib(groups,"xmlns",NS_XGROUPS);
    }

    /* check if the user already as the group listed */
    group = xmlnode_get_tag(groups,spools(p,"?id=",gid,p));
    if (group == NULL) {
        /* the group isn't there */
        xmlnode_free(groups);
        return 0;
    }

    /* Delete Node */
    xmlnode_hide(group);

    xdb_set(mi->xc,uid,NS_XGROUPS,groups);
    xmlnode_free(groups);

    return 0;
}

/**
 * handle register set requests (the actual registration with a group)
 *
 * @param mi the mod_groups_i struct containing module instance data
 * @param m the mapi_struct containing module instance data
 */
void mod_groups_register_set(mod_groups_i mi, mapi m) {
    jpacket jp = m->packet;
    pool p = jp->p;
    grouptab gt;
    xmlnode info, roster, users;
    jid uid;
    char *gid, *host, *key, *un, *gn;
    int add, both;

    /* make sure it's a valid register query */
    key = xmlnode_get_tag_data(jp->iq,"key");
    gid = strchr(pstrdup(p,jp->to->resource),'/') + 1;
    if (gid == NULL || key == NULL || jutil_regkey(key,jid_full(jp->from)) == NULL) {
        js_bounce_xmpp(m->si,jp->x,XTERROR_NOTACCEPTABLE);
        return;
    }

    host = jp->from->server;

    /* check if the group exists */
    info = mod_groups_get_info(mi,p,host,gid);
    if (info == NULL) {
        js_bounce_xmpp(m->si,jp->x,XTERROR_NOTFOUND);
        return;
    }

    uid = jid_user(jp->from);
    un = xmlnode_get_tag_data(jp->iq,"name");
    gn = xmlnode_get_tag_data(info,"name");

    /* register or unregister? */
    add = (xmlnode_get_tag(jp->iq, "remove") == NULL);
    both = (xmlnode_get_tag(info,"static") == NULL);

    if (add) {
        log_debug2(ZONE, LOGT_DELIVER, "register GID %s",gid);
        if (mod_groups_xdb_add(mi,p,uid,un ? un : jid_full(uid),gid,gn,both)) {
            js_bounce_xmpp(m->si,jp->x,XTERROR_UNAVAIL);
            xmlnode_free(info);
            return;
        }
    } else {
        log_debug2(ZONE, LOGT_DELIVER, "unregister GID %s",gid);
        if (mod_groups_xdb_remove(mi,p,uid,host,gid)) {
            js_bounce_xmpp(m->si,jp->x,XTERROR_UNAVAIL);
            xmlnode_free(info);
            return;
        }
    }

    gt = GROUP_GET(mi,gid);

    /* push the group to the user */
    if (add || xmlnode_get_tag(info,"require") == NULL) {
        users = mod_groups_get_users(mi,p,host,gid);
        if (users != NULL) {
            roster = jutil_iqnew(JPACKET__SET,NS_ROSTER);
            mod_groups_roster_insert(m->user,roster,users,gn,add);
            mod_groups_roster_push(m->s,roster,add);
        }
    }

    /* push/remove the new user to the other members */
    if (both)
        mod_groups_update_rosters(gt,uid,un,gn,add);

    /* send presnce to everyone */
    if (add && both) {
        mod_groups_presence_from(m->s,gt,m->s->presence);
        mod_groups_presence_to(m->s,gt);
    }

    jutil_iqresult(jp->x);
    jpacket_reset(jp);
    js_session_to(m->s,jp);

    xmlnode_free(info);
}

/**
 * handle a register get request
 *
 * Return what is required to register a group
 *
 * @param mi the mod_groups_i struct containing module instance data
 * @param m the mapi_struct containing the register get request
 */
void mod_groups_register_get(mod_groups_i mi, mapi m) {
    jpacket jp = m->packet;
    xmlnode q;
    char *gid, *name = "";
    xmlnode members, user;
    jid uid = m->user->id;

    gid = strchr(pstrdup(jp->p, jp->to->resource),'/');

    /* Check that it is somewhat valid */
    if (gid != NULL && *++gid != '\0') {
        jutil_iqresult(jp->x);
        q = xmlnode_insert_tag(jp->x,"query");
        xmlnode_put_attrib(q,"xmlns",NS_REGISTER);

        /* Search to see if this users is already registered */
        members = mod_groups_get_users(mi,jp->p,jp->from->server,gid);
        user =  xmlnode_get_tag(members,spools(jp->p,"?jid=",uid->full,jp->p));
        if (user) {
	    /* if the user is already registered, add the <registered/> element */
            name = xmlnode_get_attrib(user, "name");
            xmlnode_insert_tag(q,"registered");
	}
        xmlnode_free(members);

        xmlnode_insert_cdata(xmlnode_insert_tag(q,"name"),name,-1);
        xmlnode_insert_cdata(xmlnode_insert_tag(q,"key"),jutil_regkey(NULL,jid_full(jp->from)),-1);
        xmlnode_insert_cdata(xmlnode_insert_tag(q,"instructions"),mi->inst,-1);

        jpacket_reset(jp);
        js_session_to(m->s,jp);
    } else {
	/* there has been no group id in the request */
        js_bounce_xmpp(m->si,jp->x,XTERROR_NOTACCEPTABLE);
    }
}

/**
 * handle browse set requests for groups
 *
 * Only users with "edit" rights are allowed to update a group
 *
 * @param mi the mod_groups_i struct containing module instance data
 * @param m the mapi_struct containing the request
 */
void mod_groups_browse_set(mod_groups_i mi, mapi m) {
    jpacket jp = m->packet;
    pool p = jp->p;
    grouptab gt;
    xmlnode info, user;
    jid uid;
    char *gid, *gn, *un, *host, *action;
    int add;

    log_debug2(ZONE, LOGT_DELIVER, "Setting");

    /* get the group ID ... we only handle the request if there is a specified group */
    gid = strchr(jp->to->resource,'/');
    if (gid == NULL || *++gid == '\0') {
        js_bounce_xmpp(m->si,jp->x,XTERROR_NOTACCEPTABLE);
        return;
    }

    user = xmlnode_get_tag(jp->iq,"user");
    uid = jid_new(p,xmlnode_get_attrib(user,"jid"));
    un = xmlnode_get_attrib(user,"name");
    action = xmlnode_get_attrib(user, "action");
    /* it's an add action if there is no action attribute or its value is NOT remove */
    add = ( ( action == NULL ) || j_strcmp(action, "remove") );

    if (uid == NULL || un == NULL) {
        js_bounce_xmpp(m->si,jp->x,XTERROR_NOTACCEPTABLE);
        return;
    }

    /* is the user allowed to edit a group? */
    info = mod_groups_get_info(mi,p,jp->to->server,gid);
    if (info == NULL ||  xmlnode_get_tag(info,spools(p,"edit/user=",jid_full(jp->from),p)) == NULL) {
        js_bounce_xmpp(m->si,jp->x,XTERROR_NOTALLOWED);
        return;
    }
    gn = xmlnode_get_tag_data(info,"name");

    if (add) {
	/* adding a user */
        log_debug2(ZONE, LOGT_DELIVER, "Adding");
        if (mod_groups_xdb_add(mi,p,uid,un,gid,gn,1)) {
            js_bounce_xmpp(m->si,jp->x,XTERROR_UNAVAIL);
            xmlnode_free(info);
            return;
        }
    } else {
	/* removing a user */
        log_debug2(ZONE, LOGT_DELIVER, "Removing");
        host = jp->from->server;
        if (mod_groups_xdb_remove(mi,p,uid,host,gid)) {
            js_bounce_xmpp(m->si,jp->x,XTERROR_UNAVAIL);
            xmlnode_free(info);
            return;
        }
    }

    gt = GROUP_GET(mi,gid);

    /* push the new user to the other members */
    mod_groups_update_rosters(gt,uid,un,gn,add);

    /* XXX how can we push the roster to the new user and send their presence?  lookup their session? */

    xmlnode_free(info);
    jutil_iqresult(jp->x);
    jpacket_reset(jp);
    js_session_to(m->s,jp);
}

/**
 * build a result jpacket for a browse request containing the browse result for a group
 *
 * @param p the memory pool to use
 * @param jp the jpacket where to place the result
 * @param group the group for which to generate the result
 * @param host the hostname of the server
 * @param gn the group name
 */
void mod_groups_browse_result(pool p, jpacket jp, xmlnode group, char *host, char *gn) {
    xmlnode q, cur, tag;
    char *id, *name;

    q = xmlnode_insert_tag(jutil_iqresult(jp->x),"item");
    xmlnode_put_attrib(q,"xmlns",NS_BROWSE);
    xmlnode_put_attrib(q,"jid",jid_full(jp->to));
    xmlnode_put_attrib(q,"name",gn ? gn : "Toplevel groups");

    for (cur = xmlnode_get_firstchild(group); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
        if (xmlnode_get_type(cur) != NTYPE_TAG) continue;

        name = xmlnode_get_name(cur);

        if (j_strcmp(name,"group") == 0) {
            tag = xmlnode_insert_tag(q,"item");
            xmlnode_put_attrib(tag,"name",xmlnode_get_attrib(cur,"name"));
            id = spools(p,host,"/groups/",xmlnode_get_attrib(cur,"id"),p);
            xmlnode_put_attrib(tag,"jid",id);
        } else if (j_strcmp(name,"user") == 0) {
            xmlnode_insert_node(q,cur);
        }
    }
}

/**
 * handle browse-get requests by a user
 *
 * @param mi the mod_groups_i instance data
 * @param m the mapi_struct containing the browse-get-request
 */
void mod_groups_browse_get(mod_groups_i mi, mapi m) {
    jpacket jp = m->packet;
    xmlnode group;
    pool p = jp->p;
    xmlnode info = NULL;
    char *gid, *gn, *host = jp->to->server;

    log_debug2(ZONE, LOGT_DELIVER, "Browse request");

    gid = strchr(jp->to->resource,'/');
    if (gid != NULL && *++gid != '\0') {
	/* there is a group id: get this group's data */
        group = mod_groups_get_users(mi,p,host,gid);
        info = mod_groups_get_info(mi,p,host,gid);
        gn = xmlnode_get_tag_data(info,"name");
    } else {
	/* there is no group id: get the toplevel groups */
        group = mod_groups_get_top(mi,p,host);
        gn = NULL;
    }

    if (group == NULL && gn == NULL) {
        js_bounce_xmpp(m->si,jp->x,XTERROR_NOTFOUND);
        return;
    }

    if (group != NULL) {
	/* send (a) group(s) */
        mod_groups_browse_result(p,jp,group,host,gn);
        xmlnode_free(group);
    } else {
	/* there is only a name */
        xmlnode q;

        q = xmlnode_insert_tag(jutil_iqresult(jp->x),"item");
        xmlnode_put_attrib(q,"xmlns",NS_BROWSE);
        xmlnode_put_attrib(q,"jid",jid_full(jp->to));
        xmlnode_put_attrib(q,"name",gn);
    }

    /* update the jpacket with the data in jp->x */
    jpacket_reset(jp);

    /* if we return the result of a specific group (not the list), let the user register the group */
    if (gid) {
        xmlnode_insert_cdata(xmlnode_insert_tag(jp->iq,"ns"),NS_REGISTER,-1);
        xmlnode_free(info);
    }

    /* send the result to the user */
    js_session_to(m->s,jp);
}

/**
 * handle roster requests by users
 *
 * Send the user all group members of users, that are in the same groups.
 *
 * @param mi the mod_groups_i structure containing the module internal data
 * @param m the mapi_struct containing the request for the roster
 */
void mod_groups_roster(mod_groups_i mi, mapi m) {
    xmlnode groups, users, cur, roster;
    pool p;
    udata u = m->user;
    char *gid, *host = m->user->id->server;

    /* get group the user is a member of */
    if ((groups = mod_groups_get_current(mi,u->id)) == NULL)
        return;

    p = xmlnode_pool(groups);
    roster = jutil_iqnew(JPACKET__SET,NS_ROSTER);

    /* push each group */
    for (cur = xmlnode_get_firstchild(groups); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
        if (xmlnode_get_type(cur) != NTYPE_TAG) continue;

        gid = xmlnode_get_attrib(cur,"id");
        users = mod_groups_get_users(mi,p,host,gid);

        if (users != NULL) {
            xmlnode info;
            char *gn;

            info = mod_groups_get_info(mi,p,host,gid);
            gn = xmlnode_get_tag_data(info,"name");
            mod_groups_roster_insert(u,roster,users,gn ? gn : gid,1);
            xmlnode_free(info);
        } else {
            log_debug2(ZONE, LOGT_DELIVER, "Failed to get users for group");
	}
    }

    mod_groups_roster_push(m->s,roster,0);
    xmlnode_free(groups);
}

/**
 * handle iq stanzas sent to the server address
 *
 * Handled iq types are jabber:iq:roster requests, that are passed to mod_groups_roster(),
 * jabber:iq:browse to browse for groups, and jabber:iq:register to join groups.
 *
 * Browsing is delegated to mod_groups_browse_get() for get requests,
 * and mod_groups_browse_set() for set requests.
 *
 * Registeration is delegated to mod_groups_register_get() for get requests,
 * and mod_groups_register_set() for set requests.
 *
 * Requests in other namespaces to a resource that starts with "groups/" or is just
 * "groups" are rejected with an error.
 *
 * @param mi the mod_groups_i structure containing module internal data
 * @param m the mapi_struct containing the iq query
 * @return M_HANDLED if the packet has been finally handled, M_PASS if other modules should handle the packet
 */
mreturn mod_groups_iq(mod_groups_i mi, mapi m) {
    char *ns, *res;
    int type;

    ns = xmlnode_get_attrib(m->packet->iq,"xmlns");

    /* handle roster gets */
    type = jpacket_subtype(m->packet);
    if (j_strcmp(ns,NS_ROSTER) == 0) {
        if (jpacket_subtype(m->packet) == JPACKET__GET) {
            log_debug2(ZONE, LOGT_DELIVER, "Roster request");
            mod_groups_roster(mi,m);
        }
        return M_PASS;
    }

    /* handle iq's to groups */
    res = m->packet->to ? m->packet->to->resource : NULL;
    if (res && strncmp(res,"groups",6) == 0 && (strlen(res) == 6 || res[6] == '/')) {
        if (j_strcmp(ns,NS_BROWSE) == 0) {
            log_debug2(ZONE, LOGT_DELIVER, "Browse request");

            if (type == JPACKET__GET)
                mod_groups_browse_get(mi,m);
            else if (type == JPACKET__SET)
                mod_groups_browse_set(mi,m);
            else
                xmlnode_free(m->packet->x);
        } else if (j_strcmp(ns,NS_REGISTER) == 0) {
            log_debug2(ZONE, LOGT_DELIVER, "Register request");

            if (type == JPACKET__GET)
                mod_groups_register_get(mi,m);
            else if (type == JPACKET__SET)
                mod_groups_register_set(mi,m);
            else
                xmlnode_free(m->packet->x);
        } else {
            js_bounce_xmpp(m->si,m->packet->x,XTERROR_NOTALLOWED);
	}

        return M_HANDLED;
    }

    return M_PASS;
}

/**
 * handle undirected presence stanzas sent by a user
 *
 * Check if the user is member of any groups, if yes get the group configuration.
 * Send presences to all members with "subscription" both and probe all members
 * of the group for their presence.
 *
 * @param mi the mod_groups_i module instance data
 * @param m the mapi_struct containing the presence stanza
 */
void mod_groups_presence(mod_groups_i mi, mapi m) {
    grouptab gt;
    session s = m->s;
    udata u = m->user;
    xmlnode groups, cur;

    /* is the user member of any group? If not just ignore the presence */
    if ((groups = mod_groups_get_current(mi,u->id)) == NULL)
        return;

    log_debug2(ZONE, LOGT_DELIVER, "Getting groups for %s",jid_full(u->id));

    /* get each group */
    for (cur = xmlnode_get_firstchild(groups); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
        char *gid;

        if ((gid = xmlnode_get_attrib(cur,"id")) == NULL) continue;

	/* get the grouptab for this group or create a new one if it does not yet exist */
        gt = GROUP_GET(mi,gid);

        if(j_strcmp(xmlnode_get_attrib(cur,"type"),"both") == 0)
            mod_groups_presence_from(s,gt,m->packet->x);

        /* if we are new or our old priority was less then -128 then "probe" the group members */
        if (js_session_primary(m->user) || m->s->priority < -128)
            mod_groups_presence_to(s,gt);
    }

    xmlnode_free(groups);
}

/**
 * handle packets a user is sending
 *
 * If the user is sending an undirected presence stanza it is passed to mod_groups_presence() for processing
 * and always M_PASS is returned.
 *
 * If the user is sending an iq stanza, it is passed to mod_groups_iq() for processing and the
 * return value of this function is returned.
 *
 * Other stanzas than presence and iq are ignored and M_IGNORE is returned.
 *
 * @param m the mapi_struct containing the stanza
 * @param arg the mod_groups_i module instance data
 * @return M_IGNORE for other stanzas than presence and iq, M_PASS if other modules should process the packet, M_HANDLED if it is fully processed
 */
mreturn mod_groups_out(mapi m, void *arg) {
    mod_groups_i mi = (mod_groups_i) arg;

    if (m->packet->type == JPACKET_PRESENCE) {
        if (m->packet->to == NULL) mod_groups_presence(mi,m);
        return M_PASS;
    } else if (m->packet->type == JPACKET_IQ) {
        return mod_groups_iq(mi,m);
    }

    return M_IGNORE;
}

/**
 * callback to be notified about ended sessions (users that are going offline)
 *
 * @param m the mapi_struct containing the offline event
 * @param arg mod_groups_i module instance data
 * @return always M_PASS
 */
mreturn mod_groups_end(mapi m, void *arg) {
    mod_groups_i mi = (mod_groups_i) arg;
    xmlnode groups, cur;
    udata u = m->user;
    jid id = u->id;
    grouptab gt;

    if (js_session_primary(u) != NULL || (groups = mod_groups_get_current(mi,id)) == NULL)
        return M_PASS;

    log_debug2(ZONE, LOGT_DELIVER, "removing user from table");
    for (cur = xmlnode_get_firstchild(groups); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
        gt = (grouptab) xhash_get(mi->groups,xmlnode_get_attrib(cur,"id"));
        if (gt == NULL) continue;

        if(j_strcmp(xmlnode_get_attrib(cur,"type"),"both") == 0)
            xhash_zap(gt->from,jid_full(id));

        xhash_zap(gt->to,jid_full(id));
    }

    xmlnode_free(groups);
    return M_PASS;
}

/**
 * register session related callbacks if a new session is established
 *
 * @param m mapi_struct containing the session establishment request
 * @param arg pointer to the mod_groups_i structure containing module internal data
 * @return always M_PASS
 */
mreturn mod_groups_session(mapi m, void *arg) {
    js_mapi_session(es_OUT,m->s,mod_groups_out,arg);
    js_mapi_session(es_END,m->s,mod_groups_end,arg);
    return M_PASS;
}

/**
 * xhash_walker() to walk the list of members of a group and send a message to them
 *
 * @param h the xht containing the members
 * @param key unused/ignored
 * @param val the udata_struct for a single recipient
 * @param arg xmlnode containing the message
 */
void mod_groups_message_walk(xht h, const char *key, void *val, void *arg) {
    xmlnode m = (xmlnode) arg;
    udata u = (udata) val;

    m = xmlnode_dup(m);
    xmlnode_put_attrib(m,"to",jid_full(u->id));
    js_deliver(u->si,jpacket_new(m));
}

/**
 * broadcast a message to all (online) members of a group
 *
 * @param mi the mod_groups_i module instance data
 * @param msg the message to broadcast
 * @param gid to which group the message should be broadcasted
 */
void mod_groups_message_online(mod_groups_i mi, xmlnode msg, char *gid) {
    grouptab gt;

    log_debug2(ZONE, LOGT_DELIVER, "broadcast message to '%s'",gid);

    gt = (grouptab) xhash_get(mi->groups,gid);
    if (gt != NULL) {
	/* the group address becomes the sender of the message */
        xmlnode_put_attrib(msg,"from",xmlnode_get_attrib(msg,"to"));
	/* existing recipient gets replaced, hide it */
        xmlnode_hide_attrib(msg,"to");
	/* send a copy to each member of the group */
        xhash_walk(gt->from,mod_groups_message_walk,(void *) msg);
    }
    xmlnode_free(msg);
}

/**
 * handle messages sent to the server address
 *
 * only messages are handled if they are addressed to a resource of the server,
 * that starts with "groups/"
 *
 * @param m the mapi_struct containing the message
 * @param arg the mod_groups_i structure containing module configuration
 * @return M_IGNORE if not a message stanza, M_HANDLED if the packet has been handled, M_PASS else
 */
mreturn mod_groups_message(mapi m, void *arg) {
    mod_groups_i mi = (mod_groups_i) arg;
    xmlnode info;
    jpacket jp = m->packet;
    char *gid;

    if(jp->type != JPACKET_MESSAGE) return M_IGNORE;
    if(jp->to == NULL || j_strncmp(jp->to->resource,"groups/",7) != 0) return M_PASS;

    /* circular safety: do not handle messages that contain an x element in the jabber:iq:delay namespace  */
    if(xmlnode_get_tag(jp->x,"x?xmlns=" NS_DELAY) != NULL) {
        xmlnode_free(jp->x);
        return M_HANDLED;
    }

    /* process the resource, it has the form "groups/" followed by the desired group id */
    gid = strchr(jp->to->resource,'/');
    if (gid == NULL || *++gid == '\0') {
	/* there is no group id: bounce! */
        js_bounce_xmpp(m->si,jp->x,XTERROR_NOTACCEPTABLE);
        return M_HANDLED;
    }

    /* get the <info/> element for a group */
    info = mod_groups_get_info(mi,jp->p,jp->to->server,gid);
    if (info == NULL) {
	/* there is no such group available */
        js_bounce_xmpp(m->si,jp->x,XTERROR_NOTFOUND);
        return M_HANDLED;
    }

    /* check if this user has write access to the group */
    if (xmlnode_get_tag(info,spools(jp->p,"write/user=",jid_full(jp->from),jp->p)) != NULL)
        mod_groups_message_online(mi,jp->x,gid);
    else
        js_bounce_xmpp(m->si,jp->x,XTERROR_NOTALLOWED);

    xmlnode_free(info);
    return M_HANDLED;
}

/**
 * xhash_walker() used to free the content of the to and from xhashes in all grouptabs
 *
 * @param h the xht containing all groups
 * @param key the group that should be freed
 * @param val the grouptab for this group
 * @param arg unused/ignored
 */
void mod_groups_destroy(xht h, const char *key, void *val, void *arg) {
    grouptab gt = (grouptab) val;

    xhash_free(gt->to);
    xhash_free(gt->from);
}

/**
 * shutdown the module, free all allocated memory
 *
 * @param m the mapi_struct for the shutdown event
 * @param arg pointer to the mod_groups_i module internal data
 * @return always M_PASS
 */
mreturn mod_groups_shutdown(mapi m, void *arg) {
    mod_groups_i mi = (mod_groups_i) arg;

    xhash_walk(mi->groups,mod_groups_destroy,NULL);
    xhash_free(mi->groups);
    xhash_free(mi->config);
    pool_free(mi->p);

    return M_PASS;
}

/**
 * init the module, register callbacks, parse configuration
 *
 * @param si the jsmi_struct containing the Jabber session manager instance-internal data
 */
void mod_groups(jsmi si) {
    pool p;
    mod_groups_i mi;
    xmlnode cur, config;
    char *gid, *id = si->i->id;

    log_debug2(ZONE, LOGT_INIT, "initing");

    /* generate our module configuration structure */
    p = pool_new();
    mi = pmalloco(p,sizeof(_mod_groups_i));
    mi->p = p;
    mi->groups = xhash_new(67);
    mi->xc = si->xc;

    /* get the configuration xmlnode */
    config = js_config(si,"groups");
    mi->inst = xmlnode_get_tag_data(config,"instructions");
    if (mi->inst == NULL)
        mi->inst = pstrdup(p,"This will add the group to your roster");

    if (config != NULL)
    {
        mi->config = xhash_new(67);
        for (cur = xmlnode_get_firstchild(config); cur != NULL; cur = xmlnode_get_nextsibling(cur))
        {
            if (j_strcmp(xmlnode_get_name(cur),"group") != 0) continue;
            gid = xmlnode_get_attrib(cur,"id");
            if (gid == NULL)
            {
                log_error(id,"mod_groups: Error loading, no id attribute on group");
                pool_free(p);
                return;
            }
            else if (xhash_get(mi->config,gid) != NULL)
            {
                log_error(si->i->id,"mod_groups: Error loading, group '%s' configured twice",gid);
                pool_free(p);
                return;
            }

            if (xmlnode_get_tag(cur,"info") || xmlnode_get_tag(cur,"users"))
                xhash_put(mi->config,pstrdup(p,gid),cur);
        }
    }

    js_mapi_register(si,e_SERVER,mod_groups_message,(void *) mi);
    js_mapi_register(si,e_SESSION,mod_groups_session,(void *) mi);
    js_mapi_register(si,e_SHUTDOWN,mod_groups_shutdown,(void *) mi);
}
