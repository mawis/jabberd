/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "JOSL").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the JOSL. You
 * may obtain a copy of the JOSL at http://www.jabber.org/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the JOSL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the JOSL
 * for the specific language governing rights and limitations under the
 * JOSL.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 or later (the "GPL"), in which case
 * the provisions of the GPL are applicable instead of those above.  If you
 * wish to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the JOSL,
 * indicate your decision by deleting the provisions above and replace them
 * with the notice and other provisions required by the GPL.  If you do not
 * delete the provisions above, a recipient may use your version of this file
 * under either the JOSL or the GPL. 
 * 
 * --------------------------------------------------------------------------*/

#include <jabberd.h>

/** the namespace of variables in templates in the configuration */
#define NS_XDBSQL "http://jabberd.org/ns/xdbsql"

#ifdef HAVE_MYSQL
#  include <mysql/mysql.h>
#  include <mysql/errmsg.h>
#endif

#ifdef HAVE_POSTGRESQL
#  include <postgresql/libpq-fe.h>
#endif

/**
 * the maximum number of defined namespaces to handle, can be overridden with
 * the <maxns/> configuration setting
 */
#define XDBSQL_MAXNS_PRIME 101

/**
 * @file xdb_sql.c
 * @brief xdb module that handles the requests using a SQL database
 *
 * xdb_sql is an implementation of a xdb module for jabberd14, that handles
 * the xdb requests using an underlying SQL database. Currently only mysql
 * is supported.
 */

/**
 * structure that holds the data used by xdb_sql internally
 */
typedef struct xdbsql_struct {
    xht		namespace_defs;		/**< definitions of queries for the different namespaces */
    char	*onconnect;		/**< SQL query that should be executed after we connected to the database server */
    xht		namespace_prefixes;	/**< prefixes for the namespaces (key = prefix, value = ns_iri) */
    xht		std_namespace_prefixes;	/**< prefixes used by the component itself for the namespaces */
#ifdef HAVE_MYSQL
    int		use_mysql;		/**< if we want to use the mysql driver */
    MYSQL	*mysql;			/**< our database handle */
    char	*mysql_user;		/**< username for mysql server */
    char	*mysql_password;	/**< password for mysql server */
    char	*mysql_host;		/**< hostname of the mysql server */
    char	*mysql_database;	/**< database on the mysql server */
    int		mysql_port;		/**< port of the mysql server */
    char	*mysql_socket;		/**< socket of the mysql server */
    unsigned long mysql_flag;		/**< flags for the connection to the mysql server */
#endif
#ifdef HAVE_POSTGRESQL
    int		use_postgresql;		/**< if we want to use the postgresql driver */
    PGconn	*postgresql;		/**< our postgresql connection handle */
    char	*postgresql_conninfo;	/**< settings used to connect to postgresql */
#endif
} *xdbsql, _xdbsql;

/**
 * structure that holds the information how to handle a namespace
 */
typedef struct xdbsql_ns_def_struct {
    char	**get_query;		/**< SQL query to handle get requests */
    xmlnode	get_result;		/**< template for results for get requests */
    char	**set;			/**< SQL query to handle set requests */
    char	**delete;		/**< SQL query to delete old values */
} *xdbsql_ns_def, _xdbsql_ns_def;

/**
 * connect to the mysql server
 *
 * @param i the instance we are running in
 * @param xq our internal instance data
 */
void xdb_sql_mysql_connect(instance i, xdbsql xq) {
#ifdef HAVE_MYSQL
    /* connect to the database */
    if (mysql_real_connect(xq->mysql, xq->mysql_host, xq->mysql_user, xq->mysql_password, xq->mysql_database, xq->mysql_port, xq->mysql_socket, xq->mysql_flag) == NULL) {
	log_error(i->id, "failed to connect to mysql server: %s", mysql_error(xq->mysql));
    } else if (xq->onconnect) {
	xdb_sql_execute(i, xq, xq->onconnect, NULL, NULL);
    }
#else
    log_debug2(ZONE, LOGT_STRANGE, "xdb_sql_mysql_connect called, but not compiled in.");
#endif
}

/**
 * add a string to a spool while escaping some characters
 *
 * @param destination the result spool
 * @param new_string what should be added (this gets destroyed!!!)
 */
void xdb_sql_spool_add_escaped(spool destination, char *new_string) {
    char *first_to_escape = NULL;
    char *ptr = NULL;
    char character_to_escape[2] = "\0\0";

    /* check for ' */
    first_to_escape = strchr(new_string, '\'');

    /* is there a " earlier? */
    ptr = strchr(new_string, '"');
    if (ptr != NULL && (ptr < first_to_escape || first_to_escape == NULL)) {
	first_to_escape = ptr;
    }

    /* is there a \ earlier? */
    ptr = strchr(new_string, '\\');
    if (ptr != NULL && (ptr < first_to_escape || first_to_escape == NULL)) {
	first_to_escape = ptr;
    }

    /* is there something to escape? */
    if (first_to_escape == NULL) {
	/* no */
	spool_add(destination, new_string);
	return;
    }

    /* add up to the character that is escaped and this character with escapeing ... */
    character_to_escape[0] = first_to_escape[0];
    first_to_escape[0] = 0;
    spooler(destination, new_string, "\\", character_to_escape, destination);
    
    /* and call recursive */
    xdb_sql_spool_add_escaped(destination, first_to_escape+1);
}

/**
 * use the template for a query to construct a real query
 *
 * @param template the template to construct the SQL query
 * @param xdb_query the xdb query
 * @param namespaces the mapping from namespace prefixes to namespace IRIs
 * @return SQL query
 */
char *xdb_sql_construct_query(char **template, xmlnode xdb_query, xht namespaces) {
    int index = 0;		/* token counter */
    spool result_spool = spool_new(xdb_query->p); /* where to store the result */

    /* sanity check */
    if (template == NULL || xdb_query == NULL) {
	return NULL;
    }

    /* debugging */
    log_debug2(ZONE, LOGT_STORAGE, "constructing query using xdb_query %s", xmlnode_serialize_string(xdb_query, NULL, NULL, 0));

    /* construct the result */
    while (template[index] != NULL) {
	if (index % 2 == 0) {
	    /* copy token */
	    spool_add(result_spool, template[index]);
	} else {
	    /* substitute token */
	    char *subst = NULL;
	    xmlnode selected = NULL;

	    /* XXX handle multiple results */
	    selected = xmlnode_get_list_item(xmlnode_get_tags(xdb_query, template[index], namespaces), 0);
	    switch (xmlnode_get_type(selected)) {
		case NTYPE_TAG:
		    subst = xmlnode_serialize_string(selected, NULL, NULL, 0);
		    break;
		case NTYPE_ATTRIB:
		case NTYPE_CDATA:
		    subst = xmlnode_get_data(selected);
		    break;
	    }

	    log_debug2(ZONE, LOGT_STORAGE, "%s replaced by %s", template[index], subst);

	    xdb_sql_spool_add_escaped(result_spool, pstrdup(result_spool->p, subst!=NULL ? subst : ""));
	}

	/* next token */
	index++;
    }

    return spool_print(result_spool);
}

/**
 * find any node in a xmlnode tree that matches the search
 *
 * @todo something like this should become a part of xmlnode
 *
 * @param root the root of the tree we search in
 * @param name which element to search
 * @param ns_iri the namespace IRI of the element to search for
 * @return the found element, or NULL if no such element
 */
xmlnode xdb_sql_find_node_recursive(xmlnode root, const char *name, const char *ns_iri) {
    xmlnode ptr = NULL;

    /* is it already this node? */
    if (j_strcmp(xmlnode_get_localname(root), name) == 0 && j_strcmp(xmlnode_get_namespace(root), ns_iri) == 0) {
	/* we found it */
	return root;
    }

    /* check the child nodes */
    for (ptr = xmlnode_get_firstchild(root); ptr != NULL; ptr = xmlnode_get_nextsibling(ptr)) {
	xmlnode result = xdb_sql_find_node_recursive(ptr, name, ns_iri);
	if (result != NULL) {
	    return result;
	}
    }

    /* found nothing */
    return NULL;
}

/**
 * execute a sql query using mysql
 *
 * @param i the instance we are running in
 * @param xq instance internal data
 * @param query the SQL query to execute
 * @param template template to construct the result
 * @param result where to add the results
 * @return 0 on success, non zero on failure
 */
int xdb_sql_execute_mysql(instance i, xdbsql xq, char *query, xmlnode template, xmlnode result) {
#ifdef HAVE_MYSQL
    int ret = 0;
    MYSQL_RES *res = NULL;
    MYSQL_ROW row = NULL;
    
    /* try to execute the query */
    ret = mysql_query(xq->mysql, query);

    /* failed and we need to reconnect? */
    if (ret == CR_SERVER_LOST || ret == CR_SERVER_GONE_ERROR) {
	xdb_sql_mysql_connect(i, xq);

	ret = mysql_query(xq->mysql, query);
    }

    /* still an error? log and return */
    if (ret != 0) {
	log_error(i->id, "mysql query (%s) failed: %s", query, mysql_error(xq->mysql));
	return 1;
    }

    /* the mysql query succeded: fetch results */
    while (res = mysql_store_result(xq->mysql)) {
	/* how many fields are in the rows */
	unsigned int num_fields = mysql_num_fields(res);

	/* fetch rows of the result */
	while (row = mysql_fetch_row(res)) {
	    xmlnode variable = NULL;
	    xmlnode new_instance = NULL;

	    log_debug2(ZONE, LOGT_STORAGE, "we got a result row with %u fields", num_fields);
	    
	    /* instantiate a copy of the template */
	    new_instance = xmlnode_dup_pool(result->p, template);

	    /* find variables in the template and replace them with values */
	    while (variable = xdb_sql_find_node_recursive(new_instance, "value", NS_JABBERD_XDBSQL)) {
		xmlnode parent = xmlnode_get_parent(variable);
		int value = j_atoi(xmlnode_get_attrib_ns(variable, "value", NULL), 0);
		int parsed = j_strcmp(xmlnode_get_attrib_ns(variable, "parsed", NULL), "parsed") == 0;

		/* hide the template variable */
		xmlnode_hide(variable);

		/* insert the value */
		if (value > 0 && value <= num_fields) {
		    if (parsed) {
			xmlnode fieldvalue = xmlnode_str(row[value-1], j_strlen(row[value-1]));
			xmlnode fieldcopy = xmlnode_dup_pool(result->p, fieldvalue);
			xmlnode_free(fieldvalue);
			xmlnode_insert_tag_node(parent, fieldcopy);
		    } else {
			xmlnode_insert_cdata(parent, row[value-1], -1);
		    }
		}
	    }

	    /* insert the result */
	    log_debug2(ZONE, LOGT_STORAGE, "the row results in: %s", xmlnode_serialize_string(new_instance, NULL, NULL, 0));
	    xmlnode_insert_node(result, xmlnode_get_firstchild(new_instance));
	}

	/* free the result again */
	mysql_free_result(res);
    }

    return 0;
#else
    log_debug2(ZONE, LOGT_STRANGE, "xdb_sql_execute_mysql called, but not compiled in.");
    return 1;
#endif
}

/**
 * execute a sql query using postgresql
 *
 * @param i the instance we are running in
 * @param xq instance internal data
 * @param query the SQL query to execute
 * @param template template to construct the result
 * @param result where to add the results
 * @return 0 on success, non zero on failure
 */
int xdb_sql_execute_postgresql(instance i, xdbsql xq, char *query, xmlnode template, xmlnode result) {
#ifdef HAVE_POSTGRESQL
    PGresult *res = NULL;
    ExecStatusType status = 0;
    int row = 0;
    int fields = 0;

    /* are we still connected? */
    if (PQstatus(xq->postgresql) != CONNECTION_OK) {
	log_warn(i->id, "resetting connection to the PostgreSQL server");
	
	/* reset the connection */
	PQreset(xq->postgresql);

	/* are we now connected? */
	if (PQstatus(xq->postgresql) != CONNECTION_OK) {
	    log_error(i->id, "cannot reset connection: %s", PQerrorMessage(xq->postgresql));
	    return 1;
	} else if (xq->onconnect) {
	    xdb_sql_execute(i, xq, xq->onconnect, NULL, NULL);
	}
    }

    /* try to execute the query */
    res = PQexec(xq->postgresql, query);
    if (res == NULL) {
	log_error(i->id, "cannot execute PostgreSQL query: %s", PQerrorMessage(xq->postgresql));
	return 1;
    }

    /* get the status of the execution */
    status = PQresultStatus(res);
    switch (status) {
	case PGRES_EMPTY_QUERY:
	case PGRES_BAD_RESPONSE:
	case PGRES_FATAL_ERROR:
	    log_warn(i->id, "%s: %s", PQresStatus(status), PQresultErrorMessage(res));
	    PQclear(res);
	    return 1;
	case PGRES_COMMAND_OK:
	case PGRES_COPY_OUT:
	case PGRES_COPY_IN:
	    PQclear(res);
	    return 0;
    }

    /* the postgresql query succeded: fetch results */
    fields = PQnfields(res);
    for (row = 0; row < PQntuples(res); row++) {
	xmlnode variable = NULL;
	xmlnode new_instance = NULL;

	/* instantiate a copy of the template */
	new_instance = xmlnode_dup_pool(result->p, template);

	/* find variables in the template and replace them with values */
	while (variable = xdb_sql_find_node_recursive(new_instance, "value", NS_JABBERD_XDBSQL)) {
	    xmlnode parent = xmlnode_get_parent(variable);
	    int value = j_atoi(xmlnode_get_attrib_ns(variable, "value", NULL), 0);
	    int parsed = j_strcmp(xmlnode_get_attrib_ns(variable, "parsed", NULL), "parsed") == 0;

	    /* hide the template variable */
	    xmlnode_hide(variable);

	    /* insert the value */
	    if (value > 0 && value <= fields) {
		if (parsed) {
		    xmlnode fieldvalue = xmlnode_str(PQgetvalue(res, row, value-1), PQgetlength(res, row, value-1));
		    xmlnode fieldcopy = xmlnode_dup_pool(result->p, fieldvalue);
		    xmlnode_free(fieldvalue);
		    xmlnode_insert_tag_node(parent, fieldcopy);
		} else {
		    xmlnode_insert_cdata(parent, PQgetvalue(res, row, value-1), PQgetlength(res, row, value-1));
		}
	    }
	}

	/* insert the result */
	log_debug2(ZONE, LOGT_STORAGE, "the row results in: %s", xmlnode_serialize_string(new_instance, NULL, NULL, 0));
	xmlnode_insert_node(result, xmlnode_get_firstchild(new_instance));
    }

    PQclear(res);
    return 0;
#else
    log_debug2(ZONE, LOGT_STRANGE, "xdb_sql_execute_postgresql called, but not compiled in.");
    return 1;
#endif
}


/**
 * execute a sql query
 *
 * @param i the instance we are running in
 * @param xq instance internal data
 * @param query the SQL query to execute
 * @param template template to construct the result
 * @param result where to add the results
 * @return 0 on success, non zero on failure
 */
int xdb_sql_execute(instance i, xdbsql xq, char *query, xmlnode template, xmlnode result) {
#ifdef HAVE_MYSQL
    if (xq->use_mysql) {
	return xdb_sql_execute_mysql(i, xq, query, template, result);
    }
#endif
#ifdef HAVE_POSTGRESQL
    if (xq->use_postgresql) {
	return xdb_sql_execute_postgresql(i, xq, query, template, result);
    }
#endif
    log_error(i->id, "SQL query %s has not been handled by any sql driver", query);
    return 1;
}

/**
 * modify xdb query to be a result, that can be sent back
 *
 * @param p the packet that should be modified
 */
void xdb_sql_makeresult(dpacket p) {
    xmlnode_put_attrib_ns(p->x, "type", NULL, NULL, "result");
    xmlnode_put_attrib_ns(p->x, "to", NULL, NULL, xmlnode_get_attrib_ns(p->x, "from", NULL));
    xmlnode_put_attrib_ns(p->x, "from", NULL, NULL, jid_full(p->id));
}

/**
 * callback function that is called by jabberd to handle xdb requests
 *
 * @param i the instance we are for jabberd
 * @param p the packet containing the xdb query
 * @param arg pointer to our own internal data
 * @return r_DONE if we could handle the request, r_ERR otherwise
 */
result xdb_sql_phandler(instance i, dpacket p, void *arg) {
    xdbsql xq = (xdbsql)arg;	/* xdb_sql internal data */
    char *ns = NULL;		/* namespace of the query */
    xdbsql_ns_def ns_def = NULL; /* pointer to the namespace definitions */
    int is_set_request = 0;	/* if this is a set request */
    char *action = NULL;	/* xdb-set action */
    char *match = NULL;		/* xdb-set match */

    log_debug2(ZONE, LOGT_STORAGE|LOGT_DELIVER, "handling xdb request %s", xmlnode_serialize_string(p->x, NULL, NULL, 0));

    /* get the namespace of the request */
    ns = xmlnode_get_attrib_ns(p->x, "ns", NULL);
    if (ns == NULL) {
	log_debug2(ZONE, LOGT_STORAGE|LOGT_STRANGE, "xdb_sql got a xdb request without namespace");
	return r_ERR;
    }

    /* check if we know how to handle this namespace */
    ns_def = xhash_get(xq->namespace_defs, ns);
    if (ns_def == NULL) {
	log_error(i->id, "xdb_sql got a xdb request for an unconfigured namespace %s, use this handler only for selected namespaces.", ns);
	return r_ERR;
    }

    /* check the type of xdb request */
    is_set_request = (j_strcmp(xmlnode_get_attrib_ns(p->x, "type", NULL), "set") == 0);
    if (is_set_request) {
	/* set request */
	action = xmlnode_get_attrib_ns(p->x, "action", NULL);
	match = xmlnode_get_attrib_ns(p->x, "match", NULL);

	if (action == NULL) {
	    char *query = NULL;
	    
	    /* just a boring set */

	    /* start the transaction */
	    xdb_sql_execute(i, xq, "BEGIN", NULL, NULL);

	    /* delete old values */
	    query = xdb_sql_construct_query(ns_def->delete, p->x, xq->namespace_prefixes);
	    log_debug2(ZONE, LOGT_STORAGE, "using the following SQL statement for deletion: %s", query);
	    if (xdb_sql_execute(i, xq, query, NULL, NULL)) {
		/* SQL query failed */
		xdb_sql_execute(i, xq, "ROLLBACK", NULL, NULL);
		return r_ERR;
	    }

	    /* insert new values (if there are any) */
	    if (xmlnode_get_firstchild(p->x) != NULL) {
		query = xdb_sql_construct_query(ns_def->set, p->x, xq->namespace_prefixes);
		log_debug2(ZONE, LOGT_STORAGE, "using the following SQL statement for insertion: %s", query);
		if (xdb_sql_execute(i, xq, query, NULL, NULL)) {
		    /* SQL query failed */
		    xdb_sql_execute(i, xq, "ROLLBACK", NULL, NULL);
		    return r_ERR;
		}
	    }

	    /* commit the transaction */
	    xdb_sql_execute(i, xq, "COMMIT", NULL, NULL);

	    /* send result back */
	    xdb_sql_makeresult(p);
	    deliver(dpacket_new(p->x), NULL);
	    return r_DONE;
	} else if (j_strcmp(action, "insert") == 0) {
	    char *query = NULL;

	    /* start the transaction */
	    xdb_sql_execute(i, xq, "BEGIN", NULL, NULL);

	    /* delete matches */
	    if (match != NULL) {
		query = xdb_sql_construct_query(ns_def->delete, p->x, xq->namespace_prefixes);
		log_debug2(ZONE, LOGT_STORAGE, "using the following SQL statement for insert/match deletion: %s", query);
		if (xdb_sql_execute(i, xq, query, NULL, NULL)) {
		    /* SQL query failed */
		    xdb_sql_execute(i, xq, "ROLLBACK", NULL, NULL);
		    return r_ERR;
		}
	    }

	    /* insert new values if there are any */
	    if (xmlnode_get_firstchild(p->x) != NULL) {
		query = xdb_sql_construct_query(ns_def->set, p->x, xq->namespace_prefixes);
		log_debug2(ZONE, LOGT_STORAGE, "using the following SQL statement for insertion: %s", query);
		if (xdb_sql_execute(i, xq, query, NULL, NULL)) {
		    /* SQL query failed */
		    xdb_sql_execute(i, xq, "ROLLBACK", NULL, NULL);
		    return r_ERR;
		}
	    }

	    /* commit the transaction */
	    xdb_sql_execute(i, xq, "COMMIT", NULL, NULL);

	    /* send result back */
	    xdb_sql_makeresult(p);
	    deliver(dpacket_new(p->x), NULL);
	    return r_DONE;
	} else {
	    /* not supported action, probably check */
	    log_warn(i->id, "unable to handle unsupported xdb-set action '%s'", action);
	    return r_ERR;
	}
    } else {
	char *query = NULL;
	char *group_element = NULL;
	char *group_ns_iri = NULL;
	char *group_prefix = NULL;
	xmlnode result_element = p->x;

	/* get request */

	/* start the transaction */
	xdb_sql_execute(i, xq, "BEGIN", NULL, NULL);

	/* get the record(s) */
	query = xdb_sql_construct_query(ns_def->get_query, p->x, xq->namespace_prefixes);
	group_element = xmlnode_get_attrib_ns(ns_def->get_result, "group", NULL);
	group_ns_iri = xmlnode_get_attrib_ns(ns_def->get_result, "groupiri", NULL);
	group_prefix = xmlnode_get_attrib_ns(ns_def->get_result, "groupprefix", NULL);
	if (group_element != NULL) {
	    result_element = xmlnode_insert_tag_ns(result_element, group_element, group_prefix, group_ns_iri);
	    xmlnode_put_attrib(result_element, "ns", ns);
	}

	log_debug2(ZONE, LOGT_STORAGE, "using the following SQL statement for selection: %s", query);
	if (xdb_sql_execute(i, xq, query, ns_def->get_result, result_element)) {
	    /* SQL query failed */
	    xdb_sql_execute(i, xq, "ROLLBACK", NULL, NULL);
	    return r_ERR;
	}

	/* commit the transaction */
	xdb_sql_execute(i, xq, "COMMIT", NULL, NULL);

	/* construct the result */
	xdb_sql_makeresult(p);
	deliver(dpacket_new(p->x), NULL);
	return r_DONE;
    }
}

/**
 * init the mysql driver
 *
 * @param i the instance we are (jabberd's view)
 * @param xq our internal instance data
 * @param config the configuration node of this instance
 */
void xdb_sql_mysql_init(instance i, xdbsql xq, xmlnode config) {
#ifdef HAVE_MYSQL
    /* create a MYSQL handle */
    if (xq->mysql == NULL) {
	xq->mysql = mysql_init(NULL);
    }

    /* process our own configuration */
    xq->mysql_user = pstrdup(i->p, xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(config, "xdbsql:mysql/xdbsql:user", xq->std_namespace_prefixes), 0)));
    xq->mysql_password = pstrdup(i->p, xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(config, "xdbsql:mysql/xdbsql:password", xq->std_namespace_prefixes), 0)));
    xq->mysql_host = pstrdup(i->p, xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(config, "xdbsql:mysql/xdbsql:host", xq->std_namespace_prefixes), 0)));
    xq->mysql_database = pstrdup(i->p, xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(config, "xdbsql:mysql/xdbsql:database", xq->std_namespace_prefixes), 0)));
    xq->mysql_port = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(config, "xdbsql:mysql/xdbsql:port", xq->std_namespace_prefixes), 0)), 0);
    xq->mysql_socket = pstrdup(i->p, xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(config, "xdbsql:mysql/xdbsql:socket", xq->std_namespace_prefixes), 0)));
    xq->mysql_flag = j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(config, "xdbsql:mysql/xdbsql:flag", xq->std_namespace_prefixes), 0)), 0);

    /* connect to the database server */
    xdb_sql_mysql_connect(i, xq);
#else
    log_debug2(ZONE, LOGT_STRANGE, "xdb_sql_mysql_init called, but not compiled in.");
#endif
}

/**
 * init the postgresql driver
 *
 * @param i the instance we are (jabberd's view)
 * @param xq our internal instance data
 * @param config the configuration node of this instance
 */
void xdb_sql_postgresql_init(instance i, xdbsql xq, xmlnode config) {
#ifdef HAVE_POSTGRESQL
    /* process our own configuration */
    xq->postgresql_conninfo = pstrdup(i->p, xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(config, "xdbsql:postgresql/xdbsql:conninfo", xq->std_namespace_prefixes), 0)));

    /* connect to the database server */
    xq->postgresql = PQconnectdb(xq->postgresql_conninfo);

    /* did we connect? */
    if (PQstatus(xq->postgresql) != CONNECTION_OK) {
	log_error(i->id, "failed to connect to postgresql server: %s", PQerrorMessage(xq->postgresql));
    } else if (xq->onconnect) {
	xdb_sql_execute(i, xq, xq->onconnect, NULL, NULL);
    }
#else
    log_debug2(ZONE, LOGT_STRANGE, "xdb_sql_postgresql_init called, but not compiled in.");
#endif
}

/**
 * preprocess a SQL query definition
 *
 * @param i the instance we are running in
 * @param query the SQL query definition
 * @return array of preprocessed query, contains array of strings, odd entries are literals, even entries are variables
 */
char **xdb_sql_query_preprocess(instance i, char *query) {
    int count = 0;
    char *pos = NULL;
    char *next = NULL;
    char **result = NULL;

    /* check provieded parameters */
    if (i == NULL || query == NULL) {
	return NULL;
    }

    /* make a copy of the query that we can tokenize */
    query = pstrdup(i->p, query);

    /* go to the start of the query */
    pos = query;

    /* estimate the number of variables in the string */
    while ( (pos = strstr(pos, "{")) != NULL ) {
	/* don't find this variable again */
	pos++;

	/* count the number of variables */
	count++;
    }

    /* allocate memory for the array */
    result = pmalloco(i->p, (count+1)*2*sizeof(char*));

    /* tokenize the query */
    count = 0;
    pos = query;
    while (pos != NULL) {
	/* find start or end of variable
	 * if count is odd we search for end of variable
	 * if count is even we search for the begin of a variable
	 */
	next = (count % 2) ? strstr(pos, "}") : strstr(pos, "{");

	/* tokenize */
	if (next != NULL) {
	    *next = 0;
	}

	/* store the pointer to this token */
	result[count] = pos;

	/* skip the token separator { or } */
	if (next != NULL) {
	    next++;
	}

	/* next search starts where next points to */
	pos = next;
	count++;
    }

    return result;
}

/**
 * process a handler definition
 *
 * @param i the instance we are running as
 * @param xq our instance internal data
 * @param handler the handler definition
 */
void xdb_sql_handler_process(instance i, xdbsql xq, xmlnode handler) {
    char *handled_ns = NULL;	/* which namespace this definition is for */
    xdbsql_ns_def nsdef = NULL;	/* where to store the processed information */
    int count = 0;
    char *temp = NULL;
    
    log_debug2(ZONE, LOGT_INIT, "processing handler definition: %s", xmlnode_serialize_string(handler, NULL, NULL, 0));

    nsdef = pmalloco(i->p, sizeof(_xdbsql_ns_def));

    /* query the relevant tags from this handler */
    handled_ns = pstrdup(i->p, xmlnode_get_attrib_ns(handler, "ns", NULL));
    temp = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(handler, "xdbsql:get/xdbsql:query", xq->std_namespace_prefixes), 0));
    nsdef->get_query = xdb_sql_query_preprocess(i, temp);
    nsdef->get_result = xmlnode_dup_pool(i->p, xmlnode_get_list_item(xmlnode_get_tags(handler, "xdbsql:get/xdbsql:result", xq->std_namespace_prefixes), 0));
    temp = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(handler, "xdbsql:set", xq->std_namespace_prefixes), 0));
    nsdef->set = xdb_sql_query_preprocess(i, temp);
    temp = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(handler, "xdbsql:delete", xq->std_namespace_prefixes), 0));
    nsdef->delete = xdb_sql_query_preprocess(i, temp);

    /* store the read definition */
    log_debug2(ZONE, LOGT_INIT|LOGT_STORAGE, "registering namespace handler for %s", handled_ns);
    xhash_put(xq->namespace_defs, handled_ns, nsdef);
}

/**
 * read the handler configuration and generate their internal representation
 *
 * @param i the instance we are running as
 * @param xq our instance internal data
 * @param config the configuration data for this xdb_sql instance
 */
void xdb_sql_handler_read(instance i, xdbsql xq, xmlnode config) {
    xmlnode cur = NULL;		/* used to iterate through <handler/> elements */
    
    if (i == NULL || xq == NULL || config == NULL) {
	log_debug2(ZONE, LOGT_STRANGE|LOGT_INIT|LOGT_STORAGE, "called xdb_sql_handler_read with i, xq, or config as NULL");
	return;
    }

    for (cur = xmlnode_get_firstchild(config); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	/* we only care for <handler/> elements */
	if (j_strcmp(xmlnode_get_localname(cur), "handler") != 0 || j_strcmp(xmlnode_get_namespace(cur), NS_JABBERD_CONFIG_XDBSQL) != 0) {
	    continue;
	}

	/* process this handler definition */
	xdb_sql_handler_process(i, xq, cur);
    }
}

/**
 * init the xdb_sql module, called by the jabberd module loader
 *
 * @param i jabberd's data about our instance
 * @param x the <load/> xmlnode that instructed the moduleloader to load us
 */
void xdb_sql(instance i, xmlnode x) {
    xdbcache xc;		/* to fetch our configuration */
    xmlnode config = NULL;	/* our configuration */
    xdbsql xq = NULL;		/* pointer to instance internal data */
    char *driver = NULL;	/* database driver to use */
    xmlnode_list_item ns_def = NULL; /* for reading namespace prefix defintions */

    /* output a first sign of life ... :) */
    log_debug2(ZONE, LOGT_INIT, "xdb_sql loading");

    /* fetch our own configuration */
    xc = xdb_cache(i);
    if (xc != NULL) {
	config = xdb_get(xc, jid_new(xmlnode_pool(x), "config@-internal"), "jabber:config:xdb_sql");
    }
    if (config == NULL) {
	log_error(i->id, "xdb_sql failed to load its configuration");
	return;
    }

    /* create our internal data */
    xq = pmalloco(i->p, sizeof(_xdbsql));
    xq->std_namespace_prefixes = xhash_new(3);
    xhash_put(xq->std_namespace_prefixes, "xdbsql", NS_JABBERD_CONFIG_XDBSQL);
    xq->namespace_defs = xhash_new(j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(config, "xdbsql:maxns", xq->std_namespace_prefixes), 0)), XDBSQL_MAXNS_PRIME));
    xq->namespace_prefixes = xhash_new(101);

    /* get the namespace prefixes used in query definitions */
    for (ns_def = xmlnode_get_tags(config, "xdbsql:nsprefixes/xdbsql:namespace", xq->std_namespace_prefixes); ns_def != NULL; ns_def = ns_def->next) {
	const char *ns_iri = xmlnode_get_data(ns_def->node);
	const char *prefix = xmlnode_get_attrib_ns(ns_def->node, "prefix", NULL);

	if (ns_iri == NULL)
	    continue;

	xhash_put(xq->namespace_prefixes, prefix ? pstrdup(xq->namespace_prefixes->p, prefix) : "", pstrdup(xq->namespace_prefixes->p, ns_iri));
    }

    /* check if we have to execute an XML query after we connected to the database server */
    xq->onconnect = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(config, "xdbsql:onconnect", xq->std_namespace_prefixes), 0));
    log_debug2(ZONE, LOGT_EXECFLOW, "using the following query on SQL connection establishment: %s", xq->onconnect);

    /* use which driver? */
    driver = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(config, "xdbsql:driver", xq->std_namespace_prefixes), 0));
    if (driver == NULL) {
	log_error(i->id, "you have to configure which driver xdb_sql should use");
	xmlnode_free(config);
	return;
#ifdef HAVE_MYSQL
    } else if (j_strcmp(driver, "mysql") == 0) {
	xq->use_mysql = 1;		/* use mysql for the queries */
	xdb_sql_mysql_init(i, xq, config);
#endif
#ifdef HAVE_POSTGRESQL
    } else if (j_strcmp(driver, "postgresql") == 0) {
	xq->use_postgresql = 1;		/* use postgresql for the queries */
	xdb_sql_postgresql_init(i, xq, config);
#endif
    } else {
	log_error(i->id, "Your xdb_sql is compiled without support for the selected database driver '%s'.", driver);
    }

    /* read the handler defintions */
    xdb_sql_handler_read(i, xq, config);

    /* register our packet handler */
    register_phandler(i, o_DELIVER, xdb_sql_phandler, (void *)xq);

    /* free the configuration we have processed */
    xmlnode_free(config);
}
