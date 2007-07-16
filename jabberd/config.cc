/*
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2007 Matthias Wimmer
 *
 * This file is part of jabberd14.
 *
 * This software is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

/**
 * @file config.cc
 * @brief handle the configuration file
 */

#include "jabberd.h"
#include <iostream>

#define MAX_INCLUDE_NESTING 20 /**< the maximum number of nexted &lt;jabberd:include/&gt; elements in the configuration */
xht instance__ids=NULL;	/**< hash of all created XML routing target instances (key is the id of the instance, value is the ::instance) */

/**
 * list element to hold a registered shutdown callback
 */
typedef struct shutdown_list {
    pool p;		/**< memory pool: used to hold the instances memory itself */
    shutdown_func f;	/**< the registered shutdown callback function */
    void *arg;		/**< argument to pass to the shutdown callback function */
    struct shutdown_list *next;	/**< pointer to the next list element */
} _sd_list, *sd_list;
sd_list shutdown__list=NULL;	/**< list of registered shutdown callbacks */

xmlnode greymatter__ = NULL;	/**< this holds the parsed configuration file */

/**
 * check the parsed configuration file for include instructions, process these instructions, and check again
 *
 * @param nesting_lefel nesting level of includes, used to stop recursion if nesting_level is bigger than ::MAX_INCLUDE_NESTING
 * @param x the parsed configuration (modified by this function)
 */
static void do_include(int nesting_level,xmlnode x) {
    xmlnode cur;

    cur=xmlnode_get_firstchild(x);
    for(;cur!=NULL;)
    {
        if(cur->type!=NTYPE_TAG) 
        {
            cur=xmlnode_get_nextsibling(cur);
            continue;
        }
        if(j_strcmp(xmlnode_get_localname(cur),"include") == 0 && j_strcmp(xmlnode_get_namespace(cur), NS_JABBERD_CONFIGFILE_REPLACE) == 0)
        {
            xmlnode include;
            char *include_file=xmlnode_get_data(cur);
            xmlnode include_x=xmlnode_file(include_file);
            /* check for bad nesting */
            if (nesting_level>MAX_INCLUDE_NESTING) {
		std::cerr << "ERROR: Included files nested " << nesting_level << " levels deep. Possible recursion!" << std::endl;
                exit(1);
            }
            include=cur;
            xmlnode_hide(include);
            /* check to see what to insert...
             * if root tag matches parent tag of the <include/> -- firstchild
             * otherwise, insert the whole file
             */
             if (j_strcmp(xmlnode_get_localname(xmlnode_get_parent(cur)),xmlnode_get_localname(include_x)) == 0
		     && j_strcmp(xmlnode_get_namespace(xmlnode_get_parent(cur)), xmlnode_get_namespace(include_x)) == 0) {
                xmlnode_insert_node(x,xmlnode_get_firstchild(include_x));
	     } else {
		 if (j_strcmp(xmlnode_get_localname(xmlnode_get_parent(cur)), xmlnode_get_localname(include_x)) == 0) {
		     xmlnode example_root_element = xmlnode_dup(xmlnode_get_parent(cur));

		     while (xmlnode_get_firstchild(example_root_element) != NULL)
			 xmlnode_hide(xmlnode_get_firstchild(example_root_element));

		     std::cerr << "WARNING (while including file '" << include_file << "'):" << std::endl;
		     std::cerr << "Local name (" << xmlnode_get_localname(include_x) << ") of the included file's root element matches the" << std::endl;
		     std::cerr << "parent element, but namespaces are different. This means the two elements" << std::endl;
		     std::cerr << "are different and are handled as different elements. You might want this," << std::endl;
		     std::cerr << "and in that case you can just ignore this warning. But in most cases this" << std::endl;
		     std::cerr << "is a configuration bug, and not what the writer of the configuration file" << std::endl;
		     std::cerr << "intends. In that case you might want to update the root element of the" << std::endl;
		     std::cerr << "included file to declare the correct namespace." << std::endl << std::endl;
		     std::cerr << "Currently the namespace of the parent element is: " << xmlnode_get_namespace(xmlnode_get_parent(cur)) << std::endl;
		     std::cerr << "and the namespace of the included root element is: " << xmlnode_get_namespace(include_x) << std::endl;
		     std::cerr << "Waht you probably want is the following root element in the included file:" << std::endl;
		     std::cerr << xmlnode_serialize_string(example_root_element, xmppd::ns_decl_list(), 0) << std::endl << std::endl;

		     xmlnode_free(example_root_element);
		 }
                xmlnode_insert_node(x,include_x);
	     }
             do_include(nesting_level+1,include_x);
             cur=xmlnode_get_nextsibling(cur);
             continue;
        }
        else 
        {
            do_include(nesting_level,cur);
        }
        cur=xmlnode_get_nextsibling(cur);
    }
}

/**
 * replace &lt;jabberd:cmdline/&gt; elements in the configuration file with strings given at the command line
 *
 * @param x the parsed configuration file
 * @param cmd_line a hash of given command line options
 */
static void cmdline_replace(xmlnode x, xht cmd_line) {
    char *flag;
    char *replace_text;
    xmlnode cur=xmlnode_get_firstchild(x);

    for(;cur!=NULL;cur=xmlnode_get_nextsibling(cur))
    {
        if(cur->type!=NTYPE_TAG)continue;
        if(j_strcmp(xmlnode_get_localname(cur),"cmdline")!=0 || j_strcmp(xmlnode_get_namespace(cur), NS_JABBERD_CONFIGFILE_REPLACE) != 0)
        {
            cmdline_replace(cur, cmd_line);
            continue;
        }
        flag=xmlnode_get_attrib_ns(cur,"flag", NULL);
        replace_text=static_cast<char*>(xhash_get(cmd_line,flag));
        if(replace_text==NULL) replace_text=xmlnode_get_data(cur);

        xmlnode_hide(xmlnode_get_firstchild(x));
        xmlnode_insert_cdata(x,replace_text,-1);
        break;
    }
}

/**
 * activate the configured debugging settings
 *
 * @param x the parsed XML configuration file
 */
static void _set_configured_debug(xmlnode x) {
    xmlnode debug, mask, facility;
    char *debugmask, *facility_str;

    debug = xmlnode_get_tag(x, "debug");
    if (debug == NULL) {
	set_debug_flag(0);
	return;
    }

    mask = xmlnode_get_tag(debug, "mask");
    if (mask != NULL) {
	debugmask = xmlnode_get_data(mask);
	set_debug_flag(debugmask == NULL ? 0 : atoi(debugmask));
    } else {
	set_debug_flag(0);
    }

    facility = xmlnode_get_tag(debug, "facility");
    facility_str = facility == NULL ? NULL : xmlnode_get_data(facility);

    if (facility_str != NULL) {
	int facility = log_get_facility(facility_str);

	set_debug_facility(facility);

	if (facility == -1) {
	    log_alert(NULL, "debugging configuration error: unknown syslog facility: %s", facility);
	}
    } else {
	set_debug_facility(-1);
    }
}

/**
 * check the configuration if a pidfile should be written and write it
 *
 * If the pidfile already exists, the jabberd process is existed.
 *
 * @param x the parsed configuration file
 */
static void show_pid(xmlnode x) {
    xmlnode pidfile;
    char *path;
    char pidstr[16];
    int fd;
    pid_t pid;

    pidfile = xmlnode_get_tag(x, "pidfile");
    if(pidfile == NULL)
        return;

    path = xmlnode_get_data(pidfile);
    if(path == NULL)
    {
        return;
    }

    /* try to create pidfile */
    fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) {
        if (errno == EEXIST) {
	    /* the file already exists */
	    char oldpid[32] = "";
	    ssize_t bytesread = 0;

	    /* check if the process is still running */
	    fd = open(path, O_RDONLY);
	    if (fd < 0) {
		std::cerr << "The pidfile " << path << " already exists, and it cannot be opened for reading (" << strerror(errno) << "). Exiting ..." << std::endl;
		_exit(1);
	    }

	    bytesread = read(fd, oldpid, sizeof(oldpid)-1);
	    if (bytesread < 0) {
		std::cerr << "The pidfile " << path << " already exists, but there is a problem reading its content (" << strerror(errno) << "). Exiting ..." << std::endl;
		_exit(1);
	    } else if (bytesread == 0) {
		std::cerr << "The pidfile " << path << " already exists, but it has no content. Deleting it ..." << std::endl;
	    } else {
		pid_t filepid = 0;
		int killres = 0;

		oldpid[bytesread] = 0;
		filepid = j_atoi(oldpid, 0);

		if (filepid == 0) {
		    std::cerr << "The pidfile " << path << " already exists, but does not contain a PID (" << oldpid << "). Exiting ..." << std::endl;
		    _exit(1);
		}

		killres = kill(filepid, 0);
		if (killres == -1 && errno == ESRCH) {
		    std::cerr << "Stale pidfile " << path << " found. No process with PID " << filepid << " is running. Deleting pidfile ..." << std::endl;
		} else {
		    std::cerr << "A pidfile already exists at " << path << ", containing the PID (" << filepid << ") of a running process. Exiting ..." << std::endl;
		    _exit(1);
		}
	    }

	    unlink(path);
	    fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
	    if (fd < 0) {
		std::cerr << "Still having problems accessing pidfile " << path << ": " << strerror(errno) << std::endl;
		_exit(1);
	    }
        } else {
	    std::cerr << "Not writing pidfile " << path << ": " << strerror(errno) << std::endl;
	    return;
	}
    }
    pid = getpid();
    snprintf(pidstr, sizeof(pidstr), "%d", pid);
    write(fd, &pidstr, strlen(pidstr));
    close(fd);

    return;
}

/**
 * parse the configuration file, do inclusions and command line replacements
 *
 * @param file the file to parse (NULL to use the default)
 * @param cmd_line the command line arguments
 * @param is_restart 0 if it is the initial configuration processing, 1 if it is a restart
 * @return 1 on error, 0 on success
 */
int configurate(char *file, xht cmd_line, int is_restart) {
    char def[] = CONFIG_DIR"/jabber.xml";
    char *realfile = (char *)def;
    char *import_spool = NULL;
    xmlnode incl;
    char *c;

    /* if no file name is specified, fall back to the default file */
    if(file != NULL)
        realfile = file;

    /* read and parse file */
    greymatter__ = xmlnode_file(realfile);

    /* was the there a read/parse error? */
    if (greymatter__ == NULL) {
        fprintf(stderr, "Configuration parsing using %s failed: %s\n",realfile,xmlnode_file_borked(realfile));
        return 1;
    }

    /* parse -i foo.xml,bar.xml */
    if ((realfile = static_cast<char*>(xhash_get(cmd_line,"i"))) != NULL) {
        while (realfile != NULL) {
            c = strchr(realfile,',');
            if (c != NULL) {
                *c = '\0';
                c++;
            }
            if ((incl = xmlnode_file(realfile)) == NULL) {
                fprintf(stderr, "Configuration parsing included file %s failed: %s\n",realfile,xmlnode_file_borked(realfile));
                return 1;
            } else {
                xmlnode_insert_tag_node(greymatter__,incl);
                xmlnode_free(incl);
            }
            realfile = c;
        }
    }

    /* adding a spool importer if requested (-I command-line option) */
    import_spool = static_cast<char*>(xhash_get(cmd_line, "I"));
    if (import_spool != NULL) {
	xmlnode service = NULL;
	xmlnode importspool = NULL;

	service = xmlnode_insert_tag_ns(greymatter__, "service", NULL, NS_JABBERD_CONFIGFILE);
	xmlnode_put_attrib_ns(service, "id", NULL, NULL, "spoolimporter.localhost");
	importspool = xmlnode_insert_tag_ns(service, "importspool", NULL, NS_JABBERD_CONFIGFILE);
	xmlnode_insert_cdata(importspool, import_spool, -1);
    }

    /* check greymatter for additional includes */
    do_include(0,greymatter__);
    cmdline_replace(greymatter__, cmd_line);

    /* if it is the initial configuration, we have to write the PID */
    if (!is_restart)
	show_pid(greymatter__);

    _set_configured_debug(greymatter__);

    /* set locale mappings */
    if (!is_restart) {
	xht namespaces = NULL;
	xmlnode_list_item locale = NULL;

	namespaces = xhash_new(1);
	xhash_put(namespaces, "", const_cast<char*>(NS_JABBERD_CONFIGFILE));
	pool temp_pool = pool_new();
	locale = xmlnode_get_tags(greymatter__, "global/locales/locale", namespaces, temp_pool);
	xhash_free(namespaces);
	namespaces = NULL;

	for (; locale != NULL; locale = locale->next) {
	    messages_set_mapping(xmlnode_get_attrib_ns(locale->node, "lang", NULL), xmlnode_get_attrib_ns(locale->node, "locale", NULL));
	}
	pool_free(temp_pool);
    }

    return 0;
}

/**
 * private config handler list element
 */
typedef struct cfg_struct {
    char *node;			/**< name of the node, that should be handled by this handler */
    cfhandler f;		/**< function that handles the registered element */
    void *arg;			/**< argument, that should be passed to the handler function */
    struct cfg_struct *next;	/**< pointer to the next list element */
} *cfg, _cfg;

cfg cfhandlers__ = NULL;	/**< list of config handlers */

/**
 * register a function to handle that node in the config file
 *
 * @param p memory pool used to allocate data belonging to this registration
 * @param node the node that should be handled by the handler
 * @param f the handler function that should be registered
 * @param arg argument, that should be passed to the handler function
 */
void register_config(pool p, const char *node, cfhandler f, void *arg) {
    cfg newg;

    /* create and setup */
    newg = static_cast<cfg>(pmalloco(p, sizeof(_cfg)));
    newg->node = pstrdup(p,node);
    newg->f = f;
    newg->arg = arg;

    /* hook into global */
    newg->next = cfhandlers__;
    cfhandlers__ = newg;
}

/**
 * util to scan through registered config callbacks
 *
 * @param node the element name to search a handler for
 * @return the list element for this element name, NULL if nothing found
 */
static cfg cfget(char *node) {
    cfg next = NULL;

    for(next = cfhandlers__; next != NULL && strcmp(node,next->node) != 0; next = next->next);

    return next;
}

/* 
 * walk through the instance HASH, and cleanup the instances
 *
 * @param h the hashtable to walk
 * @param key the key name of the current element (instance name)
 * @param data where the key points to (the ::instance)
 * @param arg unused/ignored
 */
static void _instance_cleanup(xht h, const char *key, void *data, void *arg) {
    instance i=(instance)data;
    unregister_instance(i,i->id);
    xhash_zap(instance__ids, i->id);
    while(i->hds)
    {
        handel h=i->hds->next;
        pool_free(i->hds->p);
        i->hds=h;
    }
    pool_free(i->p);
}

void instance_shutdown(instance i);

/**
 * handle a second-level configuration file element (beside the &lt;base/&gt; element)
 *
 * @param x the configuration element to be handled
 * @param exec 0 for validation pass, 1 for real startup (init the instance)
 * @return 0 on success, 1 on error
 */
static int instance_startup(xmlnode x, int exec) {

    ptype type;
    xmlnode cur;
    cfg c;
    instance newi = NULL;
    pool p;

    type = p_NONE;

    if (j_strcmp(xmlnode_get_name(x), "pidfile") == 0)
        return 0;
    if (j_strcmp(xmlnode_get_name(x), "io") == 0)
        return 0;
    if (j_strcmp(xmlnode_get_name(x), "debug") == 0)
	return 0;
    if (j_strcmp(xmlnode_get_name(x), "global") == 0)
	return 0;

    if (j_strcmp(xmlnode_get_name(x), "log") == 0)
        type = p_LOG;
    if (j_strcmp(xmlnode_get_name(x), "xdb") == 0)
        type = p_XDB;
    if (j_strcmp(xmlnode_get_name(x), "service") == 0)
        type = p_NORM;

    if (type == p_NONE || xmlnode_get_attrib(x, "id") == NULL || xmlnode_get_firstchild(x) == NULL) {
	std::cerr << "Configuration error in:" << std::endl << xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0) << std::endl;
        if (type == p_NONE) {
	    std::cerr << "ERROR: Invalid tag type: " << xmlnode_get_name(x) << std::endl;
        }
        if (xmlnode_get_attrib(x, "id") == NULL) {
	    std::cerr << "ERROR: Section needs an 'id' attribute" << std::endl;
        }
        if (xmlnode_get_firstchild(x)==NULL) {
	    std::cerr << "ERROR: Section has no data in it" << std::endl;
        }
        return -1;
    }

    if (exec == 1) {
        newi = static_cast<instance_struct*>(xhash_get(instance__ids, xmlnode_get_attrib(x,"id")));
        if (newi != NULL) {
	    std::cerr << "ERROR: Multiple instances with same id: " << xmlnode_get_attrib_ns(x, "id", NULL) << std::endl;
            return -1;
        }
    }

    /* create the instance */
    if (exec) {
        jid temp;
        p = pool_new();
        newi = static_cast<instance_struct*>(pmalloco(p, sizeof(_instance)));
        newi->id = pstrdup(p,xmlnode_get_attrib(x,"id"));
        newi->type = type;
        newi->p = p;
        newi->x = x;
        /* make sure the id is valid for a hostname */
        temp = jid_new(p, newi->id);
        if (temp == NULL || j_strcmp(temp->server, newi->id) != 0) {
            log_alert(NULL, "ERROR: Invalid id name: %s\n",newi->id);
            pool_free(p);
            return -1;
        }
        xhash_put(instance__ids,newi->id,newi);
        register_instance(newi,newi->id);
	register_shutdown((shutdown_func)instance_shutdown, newi);
    }


    /* loop through all this sections children */
    for (cur = xmlnode_get_firstchild(x); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
        /* only handle elements */
        if (xmlnode_get_type(cur) != NTYPE_TAG)
            continue;

        /* find the registered function for this element */
        c = cfget(xmlnode_get_name(cur));

        /* if we don't have a handler, but we do have a namespace, we can just be ignored */
        if (c == NULL && xmlnode_get_attrib(cur, "xmlns") != NULL)
            continue;

        /* no handler or handler returning an error, die */
        if (c == NULL  || (c->f)(newi, cur, c->arg) == r_ERR) {
            char *error = pstrdup(xmlnode_pool(cur), xmlnode_get_attrib(cur,"error"));
            xmlnode_hide_attrib(cur, "error");
	    std::cerr << "Invalid configuration in instance '" << xmlnode_get_attrib_ns(x, "id", NULL) << ":" << std::endl;
	    std::cerr << xmlnode_serialize_string(cur, xmppd::ns_decl_list(), 0) << std::endl;
            if (c == NULL) 
		std::cerr << "ERROR: Unknown base tag: " << xmlnode_get_name(cur) << std::endl;
            else if (error != NULL)
		std::cerr << "ERROR: Base handler returned an error:" << std::endl << error << std::endl;
            return -1;
        }
    }

    return 0;
}

/**
 * execute configuration file
 *
 * @param exec 0 for the first validation pass, 1 for real startup
 * @return 0 on success, 1 on error
 */
int configo(int exec) {
    xmlnode cur;

    if (instance__ids==NULL)
	instance__ids = xhash_new(19);

    for (cur = xmlnode_get_firstchild(greymatter__); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
        if (xmlnode_get_type(cur) != NTYPE_TAG || strcmp(xmlnode_get_name(cur),"base") == 0)
            continue;

        if (instance_startup(cur, exec)) {
            return 1;
        }

    }

    return 0;
}

/**
 * shuts down a single instance, or all the instances, if i == NULL
 *
 * @param i which instance to shut down
 */
void instance_shutdown(instance i) {
    if (i != NULL) {
        unregister_instance(i,i->id);
        xhash_zap(instance__ids, i->id);
        while (i->hds) {
            handel h=i->hds->next;
            pool_free(i->hds->p);
            i->hds=h;
        }
        pool_free(i->p);
    } else {
        xhash_walk(instance__ids, _instance_cleanup, NULL);
    }
}

/**
 * call all registered shutdown callbacks
 */
void shutdown_callbacks(void) {
    while (shutdown__list) {
        sd_list s=shutdown__list->next;
        (*shutdown__list->f)(shutdown__list->arg);
        pool_free(shutdown__list->p);
        shutdown__list=s;
    }
}

/**
 * register a function to be called on shutdown
 *
 * @param f the function to be called on shutdown
 * @param arg the argument to be passed to the callback function
 */
void register_shutdown(shutdown_func f,void *arg) {
    pool p;
    sd_list newsd;
    if (f==NULL)
	return;
    
    p=pool_new();
    newsd=static_cast<sd_list>(pmalloco(p, sizeof(_sd_list)));
    newsd->p=p;
    newsd->f=f;
    newsd->arg=arg;
    newsd->next=shutdown__list;
    shutdown__list=newsd;
}
