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

#include "util.h"
#include <expat.h>

/**
 * @file config.c
 * @brief handling of the configuration
 *
 * The configuration is read as an XML file and converted to a hash containing
 * the configuration values
 */

/**
 * new config structure
 */
config_t config_new(void) {
    return xhash_new(501);
}

struct build_data {
    nad_t               nad;
    int                 depth;
};

static void _config_startElement(void *arg, const char *name, const char **atts) {
    struct build_data *bd = (struct build_data *) arg;
    int i = 0;
    
    nad_append_elem(bd->nad, (char *) name, bd->depth);
    while (atts[i] != NULL) {
        nad_append_attr(bd->nad, (char *) atts[i], (char *) atts[i + 1]);
        i += 2;
    }

    bd->depth++;
}

static void _config_endElement(void *arg, const char *name) {
    struct build_data *bd = (struct build_data *) arg;

    bd->depth--;
}

static void _config_charData(void *arg, const char *str, int len) {
    struct build_data *bd = (struct build_data *) arg;

    nad_append_cdata(bd->nad, (char *) str, len, bd->depth);
}

/**
 * turn an xml file into a config hash
 */
int config_load(config_t c, const char *file) {
    struct build_data bd;
    nad_cache_t cache = nad_cache_new();
    FILE *f;
    XML_Parser p;
    int done, len, end, i, j, attr;
    char buf[1024], *next;
    struct nad_elem_st **path;
    config_elem_t elem;

    /* open the file */
    f = fopen(file, "r");
    if (f == NULL) {
        fprintf(stderr, "config_load: couldn't open %s for reading: %s\n", file, strerror(errno));
        return 1;
    }

    /* new parser */
    p = XML_ParserCreate(NULL);
    if (p == NULL) {
        fprintf(stderr, "config_load: couldn't allocate XML parser\n");
        fclose(f);
        return 1;
    }

    /* nice new nad to parse it into */
    bd.nad = nad_new(cache);
    bd.depth = 0;

    /* setup the parser */
    XML_SetUserData(p, (void *) &bd);
    XML_SetElementHandler(p, _config_startElement, _config_endElement);
    XML_SetCharacterDataHandler(p, _config_charData);

    do {
        /* read that file */
        len = fread(buf, 1, 1024, f);
        if (ferror(f)) {
            fprintf(stderr, "config_load: read error: %s\n", strerror(errno));
            XML_ParserFree(p);
            fclose(f);
            nad_cache_free(cache);
            return 1;
        }
        done = feof(f);

        /* parse it */
        if (!XML_Parse(p, buf, len, done)) {
            fprintf(stderr, "config_load: parse error at line %d: %s\n", XML_GetCurrentLineNumber(p), XML_ErrorString(XML_GetErrorCode(p)));
            XML_ParserFree(p);
            fclose(f);
            nad_cache_free(cache);
            return 1;
        }
    } while (!done);

    /* done reading */
    XML_ParserFree(p);
    fclose(f);

    /* now, turn the nad into a config hash */
    path = NULL;
    len = 0, end = 0;
    /* start at 1, so we skip the root element */
    for (i = 1; i < bd.nad->ecur; i++) {
        /* make sure we have enough room to add this element to our path */
        if (end <= bd.nad->elems[i].depth) {
            end = bd.nad->elems[i].depth + 1;
            path = (struct nad_elem_st **) realloc((void *) path, sizeof(struct nad_elem_st *) * end);
        }

        /* save this path element */
        path[bd.nad->elems[i].depth] = &bd.nad->elems[i];
        len = bd.nad->elems[i].depth + 1;

        /* construct the key from the current path */
        next = buf;
        for (j = 1; j < len; j++) {
            strncpy(next, bd.nad->cdata + path[j]->iname, path[j]->lname);
            next = next + path[j]->lname;
            *next = '.';
            next++;
        }
        next--;
        *next = '\0';

        /* find the config element for this key */
        elem = xhash_get(c, buf);
        if (elem == NULL) {
            /* haven't seen it before, so create it */
            elem = pmalloco(xhash_pool(c), sizeof(struct config_elem_st));
            xhash_put(c, pstrdup(xhash_pool(c), buf), elem);
        }

        /* make room for this value .. can't easily realloc off a pool, so
         * we do it this way and let _config_reaper clean up */
        elem->values = realloc((void *) elem->values, sizeof(char *) * (elem->nvalues + 1));

        /* and copy it in */
        if (NAD_CDATA_L(bd.nad, i) > 0)
            elem->values[elem->nvalues] = pstrdupx(xhash_pool(c), NAD_CDATA(bd.nad, i), NAD_CDATA_L(bd.nad, i));
        else
            elem->values[elem->nvalues] = "1";

        /* make room for the attribute lists */
        elem->attrs = realloc((void *) elem->attrs, sizeof(char **) * (elem->nvalues + 1));
        elem->attrs[elem->nvalues] = NULL;

        /* count the attributes */
        for (attr = bd.nad->elems[i].attr, j = 0; attr >= 0; attr = bd.nad->attrs[attr].next, j++)
	    /* nothing */;

        /* if we have some */
        if (j > 0) {
            /* make space */
            elem->attrs[elem->nvalues] = pmalloc(xhash_pool(c), sizeof(char *) * (j * 2 + 2));
            
            /* copy them in */
            j = 0;
            attr = bd.nad->elems[i].attr;
            while (attr >= 0) {
                elem->attrs[elem->nvalues][j] = pstrdupx(xhash_pool(c), NAD_ANAME(bd.nad, attr), NAD_ANAME_L(bd.nad, attr));
                elem->attrs[elem->nvalues][j + 1] = pstrdupx(xhash_pool(c), NAD_AVAL(bd.nad, attr), NAD_AVAL_L(bd.nad, attr));

                j += 2;
                attr = bd.nad->attrs[attr].next;
            }

            /* do this and we can use j_attr */
            elem->attrs[elem->nvalues][j] = NULL;
            elem->attrs[elem->nvalues][j + 1] = NULL;
        }

        elem->nvalues++;
    }

    if (path != NULL)
        free(path);

    nad_cache_free(cache);

    return 0;
}

/**
 * get the config element for this key
 */
config_elem_t config_get(config_t c, char *key) {
    return xhash_get(c, key);
}

/**
 * get config value n for this key
 */
char *config_get_one(config_t c, char *key, int num) {
    config_elem_t elem = xhash_get(c, key);

    if (elem == NULL)
        return NULL;

    if (num >= elem->nvalues)
        return NULL;

    return elem->values[num];
}

/**
 * how many values for this key?
 */
int config_count(config_t c, char *key) {
    config_elem_t elem = xhash_get(c, key);

    if (elem == NULL)
        return 0;

    return elem->nvalues;
}

/**
 * get an attr for this value
 */
char *config_get_attr(config_t c, char *key, int num, char *attr) {
    config_elem_t elem = xhash_get(c, key);

    if (elem->attrs == NULL)
        return NULL;

    return j_attr((const char **) elem->attrs[num], attr);
}

/**
 * cleanup helper
 */
static void _config_reaper(xht h, const char *key, void *val, void *arg) {
    config_elem_t elem = (config_elem_t) val;

    free(elem->values);
    free(elem->attrs);
}

/**
 * cleanup
 */
void config_free(config_t c) {
    xhash_walk(c, _config_reaper, NULL);

    xhash_free(c);
}
