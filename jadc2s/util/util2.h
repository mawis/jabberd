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
	logmessage(logging &log_entity, int level);

	/**
	 * destructor: will write the collected message to the logging instance
	 */
	~logmessage();

	/**
	 * get the errors on the OpenSSL error stack and output them to the logmessage
	 */
	logmessage &ssl_errors();

	/**
	 * to output char* as the first text on a logging->level() rvalue
	 *
	 * @param text the string to output
	 * @return the stream on which the output has been done, can be used to output more data using the operator<<()
	 */
	std::ostream &operator<<(const char *text);
    private:
	/**
	 * copy constructor: needed by the logging class to return a logmessage instance for the level() member
	 */
	logmessage(const logmessage &orig);

	/**
	 * allow the logging class to use the copy constructor
	 */
	friend class logging;

	/**
	 * where the message will be written to at the destruction
	 */
	logging &log_entity;

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


#endif	/* UTIL2_H */
