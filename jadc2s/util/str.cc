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
 */

#include "util.h"

#include <sstream>

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
 * format a filename and a line number to a single string
 *
 * @param file the file name
 * @param line the line number
 * @return formated string (in a static buffer)
 */
char *zonestr(char *file, int line) {
    static char buff[64];

    std::ostringstream buff_stream;
    buff_stream << file << ":" << line;

    std::string result = buff_stream.str();
    if (result.length() > sizeof(buff)-1)
	result.erase(sizeof(buff)-1);

    strcpy(buff, result.c_str());

    return buff;
}
