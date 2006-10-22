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

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#ifndef UTIL_H
#define UTIL_H

#include <string>
#include <map>
#include <sstream>
#include <fstream>
#include <set>
#include <list>
#include <stack>
#include <deque>
#include <vector>
#include <stdexcept>

#include <ctime>

#include <stringprep.h>

#include <libxml++/libxml++.h>
#include <glibmm.h>


namespace xmppd {

    /* ******************** Hashes ******************** */

    /**
     * generic base class for a hash function
     */
    class hash {
	public:
	    virtual void update(const std::string& data) =0;
	    virtual std::vector<uint8_t> final() =0;
	    std::string final_hex();
    };

    /**
     * the SHA-1 hashing algorithm
     */
    class sha1 : public hash {
	public:
	    /**
	     * construct a SHA-1 hashing instance
	     */
	    sha1();

	    /**
	     * add data to what the hash should calculated for
	     *
	     * @param data the data that should get added
	     */
	    void update(const std::string& data);

	    /**
	     * signal that all data has been added and request the hash
	     *
	     * @note use final_hex() to do the same but get a string result (hex version of the result)
	     *
	     * @return the hash value (binary)
	     */
	    std::vector<uint8_t> final();
	private:
	    /**
	     * if set to true, the hash has been padded and no more data can be added
	     */
	    bool padded;

	    /**
	     * temporarily storage for blocks that have not yet been completed
	     */
	    std::vector<uint8_t> current_block;

	    /**
	     * W[0] to W[79] as defined in the SHA-1 standard
	     */
	    std::vector<uint32_t> W;

	    /**
	     * which byte of a block we are currently adding
	     *
	     * W_pos because this defines where in W where are adding the byte
	     */
	    unsigned W_pos;

	    /**
	     * H0 to H4 as defined in the SHA-1 standard
	     */
	    std::vector<uint32_t> H;

	    /**
	     * do the hashing calculations on a complete block, that is now in W[]
	     */
	    void hash_block();

	    /**
	     * the function S^n as defined in the SHA-1 standard
	     */
	    inline static uint32_t circular_shift(uint32_t X, int n);

	    /**
	     * the function f(t;B,C,D) for 0 <= t <= 19 as defined in the SHA-1 standard
	     */
	    inline static uint32_t f_0_19(uint32_t B, uint32_t C, uint32_t D);

	    /**
	     * the function f(t;B,C,D) for 20 <= t <= 39 as defined in the SHA-1 standard
	     */
	    inline static uint32_t f_20_39(uint32_t B, uint32_t C, uint32_t D);

	    /**
	     * the function f(t;B,C,D) for 40 <= t <= 59 as defined in the SHA-1 standard
	     */
	    inline static uint32_t f_40_59(uint32_t B, uint32_t C, uint32_t D);

	    /**
	     * the function f(t;B,C,D) for 60 <= t <= 79 as defined in the SHA-1 standard
	     */
	    inline static uint32_t f_60_79(uint32_t B, uint32_t C, uint32_t D);

	    /**
	     * the length of the message (l in the SHA-1 standard as well)
	     */
	    uint64_t l;
    };

    /* ******************** Logging ******************** */

#ifdef USE_SYSLOG
# include <syslog.h>
#else
# define LOG_EMERG   (0)
# define LOG_ALERT   (1)
# define LOG_CRIT    (2)
# define LOG_ERR     (3)
# define LOG_WARNING (4)
# define LOG_NOTICE  (5)
# define LOG_INFO    (6)
# define LOG_DEBUG   (7)
#endif

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
	     * Signal that is fired, if the root of the XML stream has been received
	     *
	     * @note to not expect the passed document or element to exist after all
	     * signal handlers have been processed. If you need to keep this data
	     * make a copy of it.
	     *
	     * @note the passed element is the document root element.
	     *
	     * The passed Glib::ustring is the namespace IRI of the default namespace. This
	     * will pass the original namespace IRI, even if that iri is mapped to another
	     * namespace IRI.
	     */
	    sigc::signal<void, const xmlpp::Document&, const xmlpp::Element&, const Glib::ustring&> signal_on_root;

	    /**
	     * Signal that is fired, if a stanza has been received on the XML stream
	     *
	     * @note to not expect the passed document or element to exist after all
	     * signal handlers have been processed. If you need to keep this data
	     * make a copy of it.
	     *
	     * @note the passed element is the stanza root element.
	     */
	    sigc::signal<void, const xmlpp::Document&, const xmlpp::Element&> signal_on_stanza;

	    /**
	     * Signal that is fired, if a stream has ended
	     *
	     * The bool parameter signals if the stream has been closed by a closing root element or by an
	     * error. (true = close because of an error)
	     */
	    sigc::signal<void, bool, const Glib::ustring&> signal_on_close;

	    /**
	     * sets a replacement for a namespace
	     *
	     * If a namespace is replaced, the one namespace is always replaced to the other
	     * while reading the XML document.
	     *
	     * @param replaced the namespace that gets replaced
	     * @param replacement the namespace that gets set instead
	     */
	    void set_namespace_replacement(const Glib::ustring& replaced, const Glib::ustring& replacement);

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

	    void on_error(const Glib::ustring& text);

	    xmlpp::Document stream_document;

	    std::stack<xmlpp::Element*> current_element;

	    std::map<Glib::ustring, Glib::ustring> namespace_replacements;

	    /**
	     * adds the attributes of the attributes AttributeNSList to the top of current_elements
	     *
	     * @param attributes the attributes to add
	     */
	    void add_attributes_to_current_element(const AttributeNSList& attributes);

	    /**
	     * maximum allowed depth of elements
	     */
	    unsigned int maxdepth;
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

    /* ******************** Utility for using DOMs  ******************** */

    class dom_util {
	private:
	    /* do not construct instances */
	    dom_util() {};

	public:
	    /**
	     * serialize a DOM node to its textual representation
	     *
	     * @param node the node to serialize
	     * @param known_namespaces the namespaces that are already declared where the result will be used
	     */
	    static Glib::ustring serialize_node(const xmlpp::Node& node, const std::map<Glib::ustring, Glib::ustring>& ns_replacements, const std::map<Glib::ustring, Glib::ustring>& known_namespaces, std::map<Glib::ustring, Glib::ustring>& now_defined_namespaces_out);
	    static Glib::ustring serialize_node(const xmlpp::Node& node, const std::map<Glib::ustring, Glib::ustring>& ns_replacements, const std::map<Glib::ustring, Glib::ustring>& known_namespaces);

	    /**
	     * escape characters, that should be escaped in XML
	     *
	     * @param str the string that should get escapings
	     * @result the escaped string
	     */
	    static Glib::ustring xmlescape(Glib::ustring str);
    };
}

#include "pointer.tcc"

#endif	/* UTIL_H */
