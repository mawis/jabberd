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

/**
 * @file str.c
 * @brief Handling of strings
 *
 * The j_*() functions are just helper functions, that are mostly NULL-safe versions
 * of the same libc functions.
 *
 * The spool functions can be used to add several strings to this spool and get
 * it as a single string afterwards.
 */

#include "util.h"

/**
 * Copies the content of a zero-terminated string
 *
 * @note the return value is not compatible to strcpy()!
 *
 * @param dest What to copy
 * @param txt where to copy to
 * @return pointer to the end of the result (to the 0-byte at the end of a string)
 */
static char *_j_strcpy(char *dest, char *txt) {
    if(!txt || !dest) return(dest);

    while(*txt)
        *dest++ = *txt++;
    *dest = '\0';

    return(dest);
}

/**
 * compare two strings
 *
 * @param a the one string
 * @param b the other string
 * @return 0 if both strings are the same, non-0 if both strings are different or at least one string is NULL
 */
int j_strcmp(const char *a, const char *b) {
    if (a == NULL || b == NULL)
        return -1;

    while (*a == *b && *a != '\0' && *b != '\0') {
	a++;
	b++;
    }

    if (*a == *b)
	return 0;

    return -1;
}

/**
 * compare a limited number of bytes
 *
 * compares at most i bytes, but stops before if the string ends
 *
 * @param a the one string
 * @param b the other string
 * @param i how much bytes to compare at most
 * @return 0 if both strings are the same (in the first i bytes), non-0 else of if one of the strings is NULL)
 */
int j_strncmp(const char *a, const char *b, int i) {
    if (a == NULL || b == NULL)
        return -1;
    else
        return strncmp(a, b, i);
}

/**
 * get the length of a string
 *
 * @param a the string to get the length for
 * @return the length of the string, or 0 if NULL
 */
int j_strlen(const char *a) {
    if (a == NULL)
        return 0;
    else
        return strlen(a);
}

/**
 * convert a string to an integer with a default value for NULL
 *
 * @note The default value is NOT used, if there is a string, but it cannot be parsed.
 *
 * @param a the string containing the integer
 * @param def the default value if NULL is passed as a
 * @return the converted integer
 */
int j_atoi(const char *a, int def) {
    if (a == NULL)
        return def;
    else
        return atoi(a);
}

/**
 * get a value from an array of strings containing keys at the even positions, and values at the odd positions (expat's way to pass attributes)
 *
 * @param atts the array for strings
 * @param attr which value to get (the key)
 * @return the value for the passed key
 */
char *j_attr(const char** atts, char *attr) {
    int i = 0;

    while (atts[i] != '\0') {
        if (j_strcmp(atts[i],attr) == 0)
	    return (char*)atts[i+1];
        i += 2;
    }

    return NULL;
}

/**
 * Create a new spool
 *
 * Spools can be used to add multiple strings, which can afterwards get back as a single
 * concatenated string
 *
 * @param p the memory pool to use
 * @return the spool object
 */
spool spool_new(pool p) {
    spool s;

    s = pmalloc(p, sizeof(struct spool_struct));
    s->p = p;
    s->len = 0;
    s->last = NULL;
    s->first = NULL;
    return s;
}

/**
 * Add a string to the spool
 *
 * Adds the content of a string to the end of a spool
 *
 * @note use spool_add() instead, which is a NULL-safe version of this.
 *
 * @param s the spool to add the string to
 * @param goodstring the string to add (must not be freed before the spool is printed)
 */
static void _spool_add(spool s, char *goodstr) {
    struct spool_node *sn;

    sn = pmalloc(s->p, sizeof(struct spool_node));
    sn->c = goodstr;
    sn->next = NULL;

    s->len += strlen(goodstr);
    if (s->last != NULL)
        s->last->next = sn;
    s->last = sn;
    if (s->first == NULL)
        s->first = sn;
}

/**
 * Add a string to the spool
 *
 * Adds the content of a string to the end of a spool
 *
 * @param s the spool to add the string to
 * @param goodstring the string to add (must not be freed before the spool is printed)
 */
void spool_add(spool s, char *str) {
    if (str == NULL || strlen(str) == 0)
        return;

    _spool_add(s, pstrdup(s->p, str));
}

/**
 * Prints all strings that have been added to the spool to a new string
 *
 * @param s the spool that should be printed
 * @return the new string
 */
char *spool_print(spool s) {
    char *ret,*tmp;
    struct spool_node *next;

    if (s == NULL || s->len == 0 || s->first == NULL)
        return NULL;

    ret = pmalloc(s->p, s->len + 1);
    *ret = '\0';

    next = s->first;
    tmp = ret;
    while (next != NULL) {
        tmp = _j_strcpy(tmp,next->c);
        next = next->next;
    }

    return ret;
}

/**
 * convenience function, that does the spool creation, string adding, and printing all at once
 *
 * Add all strings, that should be printed to the parameter list, and terminate by passing p again
 *
 * @param p the memory pool to use
 * @return the printed string
 */
char *spools(pool p, ...) {
    va_list ap;
    spool s;
    char *arg = NULL;

    if (p == NULL)
        return NULL;

    s = spool_new(p);

    va_start(ap, p);

    /* loop till we hit our end flag, the first arg */
    for (arg = va_arg(ap, char *); (pool)arg != p; arg = va_arg(ap, char *)) {
	spool_add(s, arg);
    }

    va_end(ap);

    return spool_print(s);
}

/**
 * format a filename and a line number to a single string
 *
 * @param file the file name
 * @param line the line number
 * @return formated string (in a static buffer)
 */
char *zonestr(char *file, int line) {
    static char buff[64];
    int i;

    i = snprintf(buff,63,"%s:%d",file,line);
    buff[i] = '\0';

    return buff;
}
