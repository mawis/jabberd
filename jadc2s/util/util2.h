/*
 * Licence
 *
 * Copyright (c) 2006 Matthias Wimmer,
 *                    mailto:m@tthias.eu, xmpp:mawis@amessage.info
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
#include <list>
#include <stack>
#include <deque>

#include <ctime>

#include <stringprep.h>

#include <libxml++/libxml++.h>
#include <glibmm.h>


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

	    /**
	     * to output std::string as the first text on a logging->level() rvalue
	     *
	     * @param text the string to output
	     * @return the stream on which the output has been done, can be used to output more data using the operator<<()
	     */
	    std::ostream& operator<<(const std::string& text);
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
	    logging(Glib::ustring ident);

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
	    void write(int level_to_use, Glib::ustring log_message);

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
	    Glib::ustring identity;
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
	     * constructor to create a managed pointer pointing to nothing
	     */
	    pointer() { pointer(NULL); };

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
	    pointed_type* operator->() const;

	    /**
	     * check if this pointer points to nothing
	     *
	     * @return true if the pointer does not point to anything, else false
	     */
	    bool points_to_NULL() const;
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


    /* ******************** JabberID management ******************** */

    /**
     * class caching stringprep results
     */
    class stringprep_cache {
	public:
	    /**
	     * create a stringprep cache for the given stringprep profile
	     *
	     * @param profile the stringprep profile to use for this cache
	     */
	    stringprep_cache(const ::Stringprep_profile *profile);

	    /**
	     * clean old entries from the stringprep cache
	     *
	     * @param seconds remove all entries oder then this number of seconds
	     */
	    void clean_cache(std::time_t seconds = 900);

	    /**
	     * get a stringpreped string (and cache the result)
	     *
	     * @param in_out_string string that should be stringpreped (in place)
	     * @return stringprep result
	     */
	    int stringprep(Glib::ustring &in_out_string);
	private:

	    /**
	     * a single entry in a stringprep cache
	     */
	    struct stringprep_cache_entry {
		public:
		    /**
		     * the result for the preparation
		     *
		     * empty if unchanged
		     */
		    Glib::ustring preped;

		    /**
		     * when this result has been used the last time
		     */
		    time_t last_used;

		    /**
		     * how often this result has been used
		     */
		    unsigned int used_count;
	    };

	    /**
	     * the hash table containing the stringpreped strings
	     */
	    std::map<Glib::ustring, stringprep_cache_entry> hashtable;

	    /**
	     * the stringprep profile used for this cache
	     */
	    const ::Stringprep_profile *profile;
    };

    /**
     * structure that holds the stringprep caches needed to stringprep a JID
     */
    struct jid_environment {
	public:
	    /**
	     * create all necessary caches
	     */
	    jid_environment();

	    /**
	     * stringprep_cache for nodes
	     */
	    pointer<stringprep_cache> nodes;

	    /**
	     * stringprep_cache for domains
	     */
	    pointer<stringprep_cache> domains;

	    /**
	     * stringprep_cache for resources
	     */
	    pointer<stringprep_cache> resources;
    };

    /**
     * class that holds a JabberID
     */
    class jid {
	public:
	    /**
	     * create a new JID instance using a string containing a JabberID
	     *
	     * @param environment The jid_environment used for stringpreping the parts in the JID
	     * @param address_string a string used to construct the initial jid content
	     */
	    jid(jid_environment environment, Glib::ustring address_string);

	    bool operator==(const jid &other_jid);

	    bool cmpx(const jid &other_jid, bool cmp_node = true, bool cmp_resource = false, bool cmp_domain = true);

	    void set_node(Glib::ustring new_node);

	    void set_domain(Glib::ustring new_domain);

	    void set_resource(Glib::ustring new_resource);

	    const Glib::ustring& get_node();
	    bool has_node();
	    const Glib::ustring& get_domain();
	    bool has_domain();
	    const Glib::ustring& get_resource();
	    bool has_resource();

	    const Glib::ustring &full() const;
	private:
	    Glib::ustring node;
	    Glib::ustring domain;
	    Glib::ustring resource;
	    mutable Glib::ustring full_cache;
	    jid_environment environment;
    };

    /**
     * print out a jid
     */
    std::ostringstream &operator<<(std::ostringstream &stream, const jid address);

    /* ******************** XML parsing ******************** */

    class nsparser : public xmlpp::SaxParser {
	public:
	    static const Glib::ustring NS_XMLNS;
	    static const Glib::ustring NS_EMPTY;
	    static const Glib::ustring NS_XML;

	    /**
	     * Constructor
	     *
	     * Creates a namespace aware, SAX like parser instance
	     */
	    nsparser(bool use_get_entity=false);

	    /**
	     * xml namespace aware structure that holds attributes
	     */
	    struct AttributeNS {
		/**
		 * construct a structure instance
		 *
		 * @param localname the local name of the attribute
		 * @param ns_prefix the namespace prefix of the attribute
		 * @param ns_iri the namespace IRI of the attribute
		 * @param value the value of the attribute
		 */
		AttributeNS(const Glib::ustring& localname, const Glib::ustring& ns_prefix, const Glib::ustring& ns_iri, const Glib::ustring& value) {
		    this->localname = localname;
		    this->ns_prefix = ns_prefix;
		    this->ns_iri    = ns_iri;
		    this->value     = value;
		}

		/**
		 * the localname of the attribute
		 */
		Glib::ustring localname;

		/**
		 * the namespace prefix of the attribute
		 */
		Glib::ustring ns_prefix;

		/**
		 * the namespace IRI of the attribute
		 */
		Glib::ustring ns_iri;

		/**
		 * the value of the attribute
		 */
		Glib::ustring value;
	    };

	    typedef std::deque< AttributeNS > AttributeNSList;

	    /**
	     * event for a start element
	     *
	     * @param localname the local name of the element
	     * @param ns_prefix the namespace prefix used by the element
	     * @param ns_iri the namespace IRI the element is in
	     * @param attributes the attributes on this start element
	     */
	    virtual void on_start_element_ns(const Glib::ustring& localname, const Glib::ustring& ns_prefix, const Glib::ustring& ns_iri, const AttributeNSList& attributes);

	    /**
	     * event for an end element
	     *
	     * @param localname the local name of the element
	     * @param ns_prefix the namespace prefix used by the element
	     * @param ns_iri the namespace IRI the element is in
	     */
	    virtual void on_end_element_ns(const Glib::ustring& localname, const Glib::ustring& ns_prefix, const Glib::ustring& ns_iri);

	protected:
	    /**
	     * Stack defining the mappings from namespace prefixes to namespace IRIs
	     *
	     * Each map on the stack if for an anchestor level of XML nodes. Each map
	     * in the stack contains a mapping from the prefix as the key to the IRI
	     * as the value.
	     */
	    std::stack< std::map < Glib::ustring, std::pair<Glib::ustring, int> > > ns_mappings;

	    /**
	     * The number of elements, that we read a start tag, but now end tag yet
	     */
	    unsigned int open_elements;
	private:
	    void on_start_element(const Glib::ustring& name, const AttributeList& attributes);
	    void on_end_element(const Glib::ustring& name);

	    /**
	     * if attributes declaring namespaces should be passed as attributes to on_start_element_ns()
	     */
	    bool pass_ns_definitions;
    };

    /**
     * The xmlistream class parses a continuous stream of XML data and fires events for the root node start tag
     * as well as for each completely received second level element (=stanza)
     */
    class xmlistream : public nsparser {
	public:
	    /**
	     * create a new instance of an xmlistream
	     */
	    xmlistream(bool use_get_entity=false);

	    /**
	     * event that notifies, that the root node start tag has been received
	     *
	     * @param root_element the root element that has just been read (the element is only garanteed to be valid until this method returns)
	     */
	    virtual void on_root_element(const xmlpp::Document& document, const xmlpp::Element& root_element);

	    /**
	     * event that a second level element has been received completely
	     */
	    virtual void on_stanza(const xmlpp::Document& document, const xmlpp::Element& stanza_root);

	private:
	    /**
	     * handler for the sax element, that notifies us of a received start tag
	     */
	    void on_start_element_ns(const Glib::ustring& localname, const Glib::ustring& ns_prefix, const Glib::ustring& ns_iri, const AttributeNSList& attributes);

	    void on_start_element_root(const Glib::ustring& localname, const Glib::ustring& ns_prefix, const Glib::ustring& ns_iri, const AttributeNSList& attributes);

	    /**
	     * handler for the sax element, that notifies us of a received end tag
	     */
	    void on_end_element_ns(const Glib::ustring& localname, const Glib::ustring& ns_prefix, const Glib::ustring& ns_iri);

	    void on_characters(const Glib::ustring& characters);

	    xmlpp::Document stream_document;

	    std::stack<xmlpp::Element*> current_element;

	    /**
	     * adds the attributes of the attributes AttributeNSList to the top of current_elements
	     *
	     * @param attributes the attributes to add
	     */
	    void add_attributes_to_current_element(const AttributeNSList& attributes);
    };


    /* ******************** Configuration handling ******************** */

    /**
     * structure that holds a single configuration item, optionally tagged with
     * attributes
     */
    struct configuration_entry {
	public:
	    Glib::ustring value;					/**< the configured value */
	    std::map<Glib::ustring, Glib::ustring> attributes;	/**< attributes of the value */
    };

    class configuration : public std::map<Glib::ustring, std::list<configuration_entry> >, protected xmlpp::SaxParser {
	public:
	    /**
	     * constructor that read a configuration from an XML file
	     *
	     * @param configfile the configuration file to read
	     */
	    configuration(const Glib::ustring& configfile);

	    /**
	     * destructor for a configuration instance
	     */
	    ~configuration();

	    /**
	     * get a configuration value as a string
	     */
	    const Glib::ustring& get_string(const Glib::ustring& what);

	    /**
	     * get a configuration value as an integer
	     */
	    int get_integer(const Glib::ustring& what);

	    /**
	     * sets the default value, that is returned if a configuration key is not set
	     */
	    void set_default(const Glib::ustring& what, const Glib::ustring& value);
	private:
	    std::stack<Glib::ustring> path_stack;
	    Glib::ustring parse_buffer;

	    void on_start_element(const Glib::ustring& name, const AttributeList& attributes);
	    void on_end_element(const Glib::ustring& name);
	    void on_characters(const Glib::ustring& text);

	    std::map<Glib::ustring, Glib::ustring> default_settings;
    };
}

#include "pointer.tcc"

#endif	/* UTIL2_H */
