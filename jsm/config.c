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
 *
 *  config.c
 *  Functions to handle loading and querying the server configuration file
 */

#include "jsm.h"

/*
 *  Global variable: js_config
 *  js_config is a pointer to the root node of configuration tree
 */
xmlnode js__config = NULL;
char *js__hostname;

/*
 *  js_config_load -- load the server config file
 *  Reads an XML configuration file and stores a pointer to the root
 *  node in the global variable js_config
 *
 *  parameters
 *      file -- filename of the config file to read
 *
 *  returns
 *      1 if there is a valid configuration (even if the load failed)
 *      0 if there is no configuration available
 */
int js_config_load(char *file)
{

    return 1;

}


/*
 *  js_config -- get a configuration node
 *
 *  parameters
 *      query -- the path through the tag hierarchy of the desired tag
 *               eg. for the conf file <foo><bar>bar value</bar><baz/><foo>
 *               use "foo/bar" to retreive the bar node
 *
 *  returns
 *      a pointer to the xmlnode specified in query
 *      or the root config node if query is null
 */
xmlnode js_config(char *query)
{

    log_debug(ZONE,"config query %s",query);

    /* was a query specified? */
    if(query == NULL)

        /* return the root config node */
        return js__config;    else

        /* return the specified tag */
        return xmlnode_get_tag(js__config, query);}

/* FIXME: this should be in a header file somewhere! */
struct name_list
{
    char *name;
    struct name_list *next;
};


/*
 *  js_config_name -- manipulate the global list of hostnames that this server responds to
 *  This is a special internal name resolver for the dns name(s) of this transport.
 *  Use it to check if a name is local.
 *
 *  parameters
 *      cmd -- one of the commands #defined in jsm.h
 *      name -- the hostname in question
 *
 *  returns
 *      1 if name is in the name list
 *      0 if not, or on an attempt to add a name alreay on the list
 */
int js_config_name(command cmd, char *name)
{
    static struct name_list *names;     /* the list of hostnames the server is listening on */
    struct name_list *n;                /* loop variable */
    xmlnode cur;                        /* pointer to XML node: used to read hostnames from the config file */

    log_debug(ZONE,"name %d for %s",cmd,name);

    /* handle different commands */
    switch(cmd)    {

        /* add a hostname to the list - only intended to be run at config/startup time */
    case C_SET:

        /* make sure that there is a name and it hasn't already been added */
        if(js_config_name(C_CHECK,name) || name == NULL)
            return 0;

        /* build the the list node */
        n = malloc(sizeof(struct name_list));
        n->name = strdup(name);

        /* push it onto the list head */
        n->next = names;
        names = n;
        break;

        /* see if a name is already on the list */
    case C_CHECK:

        /* traverse the name list in a loop comparing each name to the name to check */
        for(n = names; n != NULL; n = n->next)
            if(j_strcmp(name,n->name) == 0)
                return 1;
        break;

        /* build the name list from the hostname in the config file */
    case C_INIT:

        /* set default hostname */
        js__hostname = xmlnode_get_data(js_config("names/default"));

        /* enforce */
        if(js__hostname == NULL)
        {
            log_error("jsm","Unable to determine default hostname! (check config file)");
            raise(SIGTERM);
        }

        /* traverse all the tags inside the "names" tag */
        for(cur = xmlnode_get_firstchild(js_config("names")); cur != NULL; cur = xmlnode_get_nextsibling(cur))

            /* does this tag specify a hostname? */
            if(xmlnode_get_type(cur) == NTYPE_TAG)

                /* this is a hostname, add it to the list */
                js_config_name(C_SET,xmlnode_get_data(cur));
        break;

    default:
    }

    /* FIXME: need to rationalize the return values for this function */
    return 0;

}
