/*
 * Licence
 *
 * You can use the content of this file using one of the following licences:
 *
 * - Version 1.0 of the Jabber Open Source Licence ("JOSL")
 * - GNU GENERAL PUBLIC LICENSE, Version 2 or any newer version of this licence at your choice
 * - Apache Licence, Version 2.0
 * - GNU Lesser General Public License, Version 2.1 or any newer version of this licence at your choice
 * - Mozilla Public License 1.1
 */

#ifndef UTIL2_H
#define UTIL2_H

#include <string>
#include <map>
#include <sstream>
#include <fstream>
#include <set>

namespace xmppd {

    /* ******************** Logging ******************** */

    /* forward declaration */
    class logging;

    /**
     * outstream used to generate a logging line
     *
     * A user may write as he writes to a normal stream. On destruction the written data will be sent to the log.
     */
    class logmessage : public std::ostringstream {
	public:
	    /**
	     * instantiate a logmessage instance, which will use the logging level level
	     *
	     * @param log_entity where the message will be written to
	     * @param level the logging level to use
	     */
	    logmessage(logging& log_entity, int level);

	    /**
	     * destructor: will write the collected message to the logging instance
	     */
	    ~logmessage();

	    /**
	     * get the errors on the OpenSSL error stack and output them to the logmessage
	     */
	    logmessage& ssl_errors();

	    /**
	     * to output char* as the first text on a logging->level() rvalue
	     *
	     * @param text the string to output
	     * @return the stream on which the output has been done, can be used to output more data using the operator<<()
	     */
	    std::ostream& operator<<(const char* text);
	private:
	    /**
	     * copy constructor: needed by the logging class to return a logmessage instance for the level() member
	     */
	    logmessage(const logmessage& orig);

	    /**
	     * allow the logging class to use the copy constructor
	     */
	    friend class logging;

	    /**
	     * where the message will be written to at the destruction
	     */
	    logging& log_entity;

	    /**
	     * which level to use for logging
	     */
	    int level;
    };

    /**
     * The logging class is used to send messages to a logging entity
     */
    class logging {
	public:
	    /**
	     * instantiate a logging entity using the given identity
	     *
	     * @param ident the identity to use for logging
	     */
	    logging(std::string ident);

	    /**
	     * destruct the logging instance
	     */
	    ~logging();

	    /**
	     * get a logmessage instance to write a log message to
	     *
	     * @param level_to_use logging level to use for this message
	     */
	    logmessage level(int level_to_use);
	private:
	    /**
	     * write a message to the log
	     *
	     * @param level_to_use log level to use for writing
	     * @param log_message which message to log
	     */
	    void write(int level_to_use, std::string log_message);

	    /**
	     * the logmessage class needs to call the write method
	     */
	    friend class logmessage;

#ifndef USE_SYSLOG
	    /**
	     * the file where log messages get written to if syslog is not used
	     */
	    std::ofstream logfile;
#endif

	    /**
	     * the identity that is used for logging
	     */
	    std::string identity;
    };

    /* ******************** Managed pointers ******************** */

    /**
     * the pointer template class is used as a replacement for real pointers
     *
     * Instead of real pointers this template class should be used everywhere
     * inside this package. Managed pointers have the advantage, that they
     * track for you if the object pointed to does still exist.
     */
    template<class pointed_type> class pointer {
	public:
	    /**
	     * constructor to create a managed pointer for a real pointer
	     *
	     * After constructing a managed pointer, the freeing of the pointed_object is
	     * done by the managed pointer. Therefore the caller should not free the
	     * pointed_object itself.
	     *
	     * @param pointed_object the object a managed pointer should be created for
	     * @param malloc_allocated if false, the pointed_object is deleted using the delete operator (default);
	     * if true, the pointed object is deleted using std::free()
	     */
	    pointer(pointed_type* pointed_object, bool malloc_allocated = false);

	    /**
	     * copy constructor
	     *
	     * Makes a copy of a managed pointer to an object.
	     *
	     * @param src the copy source
	     */
	    pointer(const pointer<pointed_type>& src);

	    /**
	     * destruct a pointer
	     *
	     * Destructs a pointer, and if it is the last pointer to the object, it
	     * deletes (or frees) the object
	     */
	    ~pointer();

	    /**
	     * delete the object the pointer points to
	     *
	     * This marks all managed pointers pointing to this object as pointing to
	     * nothing.
	     */
	    void delete_object();

	    /**
	     * assignment operator
	     *
	     * Assignes the value of another managed pointer to a managed pointer
	     *
	     * @param src the object, that gets assigned to this managed pointer
	     * @return the managed pointer itself
	     */
	    pointer<pointed_type>& operator=(const pointer<pointed_type>& src);

	    /**
	     * dereference operator
	     *
	     * Dereferences a managed pointer (i.e. gives access to the object the
	     * managed pointer points to)
	     *
	     * @return the object the managed pointer points to
	     */
	    pointed_type& operator*();

	    /**
	     * pointer operator
	     *
	     * @note do NOT use this to get back a real pointer to the object. The operator
	     * is just there to let you access the object like you are used to do it
	     * with real pointers. (i.e. myptr->fieldname)
	     *
	     * @return the real pointer to the object
	     */
	    pointed_type* operator->();
	private:
	    /**
	     * let the pointer point to nothing
	     */
	    void point_nothing();

	    /**
	     * real pointer to the object the managed pointer points to
	     */
	    pointed_type* pointed_object;

	    /**
	     * real pointer to the set of all managed pointers to the object
	     */
	    std::set<pointer<pointed_type>*>* all_pointers_to_this_object;

	    /**
	     * default is that we delete an object we point to, but we may also use std::free() instead
	     *
	     * If true, std::free() will be used to delete object; else delete operator will be used
	     */
	    bool malloc_allocated;
    };
}

#include "pointer.tcc"

#endif	/* UTIL2_H */
