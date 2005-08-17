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
 * 
 * --------------------------------------------------------------------------*/

/**
 * @file base_dir.c
 * @brief base module base_dir: reads stanzas that are placed in a directory and processes them
 *
 * This module is can be used to periodically read a directory and check if new files
 * are in this directory. If there are, this base module will read these files, parse
 * them and handle them as stanzas.
 *
 * This can be used to generate Jabber messages in other programs, e.g. for web integration of jabberd.
 */

#include "jabberd.h"
#include <dirent.h>

/**
 * hold data this instance of base_dir needs to be passed as void* pointer
 */
typedef struct base_dir_struct {
    instance	id;		/**< the instance this base_dir is running in */
    char*	in_dir;		/**< the directory that is monitored */
    char*	out_dir;	/**< where stanzas are written */
    int		serial;		/**< serial number for writing stanzas */
} *base_dir_st, _base_dir_st;

/**
 * check the directory for new stanzas
 *
 * @param arg pointer to base_dir_struct
 * @return r_DONE on success, r_UNREG if we want to unregister the beat
 */
result base_dir_read(void *arg) {
    base_dir_st conf_data = (base_dir_st)arg;
    struct dirent *dir_ent = NULL;
    DIR *dir = NULL;
    pool p = NULL;
    char *filename = NULL;
    xmlnode x = NULL;
    jpacket jp = NULL;

    /* open the directory */
    dir = opendir(conf_data->in_dir);

    /* could it be opened? */
    if (dir == NULL) {
	log_error(conf_data->id->id, "could not open directory %s for reading", conf_data->in_dir);
	return r_UNREG;
    }

    p = pool_new();

    /* read the files in this directory */
    while ((dir_ent = readdir(dir)) != NULL) {
	/* we only care for stanzas */
	if (j_strlen(dir_ent->d_name) < 7) {
	    continue;
	}
	if (j_strcmp(dir_ent->d_name + j_strlen(dir_ent->d_name) - 7, ".stanza") != 0) {
	    continue;
	}

	/* get the full filename */
	filename = spools(p, conf_data->in_dir, "/", dir_ent->d_name, p);

	/* process the stanza file */
	x = xmlnode_file(filename);
	jp = jpacket_new(x);
	if (jp != NULL && (jp->type != JPACKET_UNKNOWN || j_strcmp(xmlnode_get_name(x), "route")==0)) {
	    deliver(dpacket_new(x), conf_data->id);
	} else {
	    log_warn(conf_data->id->id, "deleted invalid stanza %s", filename);
	    xmlnode_free(x);
	}

	/* delete the file */
	unlink(filename);

	log_debug2(ZONE, LOGT_IO, "found file %s", filename);
    }

    /* close directory, free memory and return */
    closedir(dir);
    pool_free(p);
    return r_DONE;
}

/**
 * processing outgoing stanzas
 *
 * write stanzas to files
 */
result base_dir_deliver(instance id, dpacket p, void *arg) {
    base_dir_st conf_data = (base_dir_st)arg;
    char serial[9];
    char timestamp[25];

    /* check the parameters */
    if (id == NULL || p == NULL || conf_data == NULL) {
	return r_ERR;
    }

    /* get string for the serial */
    snprintf(serial, sizeof(serial), "%08x", conf_data->serial++);

    /* write to file */
    return xmlnode2file(spools(p->p, conf_data->out_dir, "/", id->id, "-", jutil_timestamp_ms(timestamp), "-", serial, ".out", p->p), p->x) > 0 ? r_DONE : r_ERR;
}

/**
 * configuration handling
 *
 * @param id the instance to handle the configuration for, NULL for only validating the configuration
 * @param x the <dir/> element that has to be processed
 * @param arg unused/ignored
 * @return r_ERR on error, r_PASS on success
 */
result base_dir_config(instance id, xmlnode x, void *arg) {
    base_dir_st conf_data = NULL;
    
    /* nothing has to be done for configuration validation */
    if(id == NULL) {
        return r_PASS;
    }

    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_dir configuring instance %s", id->id);

    /* process configuration */
    conf_data = pmalloc(id->p, sizeof(_base_dir_st));
    conf_data->in_dir = pstrdup(id->p, xmlnode_get_tag_data(x, "in"));
    conf_data->out_dir = pstrdup(id->p, xmlnode_get_tag_data(x, "out"));
    conf_data->id = id;
    conf_data->serial = 0;

    /* read legacy configuration: no subelement of the dir element */
    if (conf_data->in_dir == NULL && conf_data->out_dir == NULL) {
	conf_data->in_dir = conf_data->out_dir = xmlnode_get_data(x);

	/* still no configuration? */
	if (conf_data->in_dir == NULL) {
	    log_alert(id->id, "ERROR in instance %s: <dir>...</dir> element needs at least one directory as an argument", id->id);
	    return r_ERR;
	} else {
	    log_notice(id->id, "Better use the elements <in/> and <out/> inside the <dir/> element to configure the base_dir handler");
	}
    }

    /* register beat for regular check directory for incoming stanzas */
    if (conf_data->in_dir != NULL) {
	register_beat(1, base_dir_read, (void*)conf_data);
    }

    /* register handler for outgoing stanzas */
    if (conf_data->out_dir != NULL) {
	register_phandler(id, o_DELIVER, base_dir_deliver, (void*)conf_data);
    }

    return r_DONE;
}

/**
 * load the base_dir base module by registering a configuration handler for <dir/>
 */
void base_dir(void) {
    log_debug2(ZONE, LOGT_INIT, "base_dir loading...");
    register_config("dir", base_dir_config, NULL);
}