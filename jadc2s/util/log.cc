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

/**
 * @file log.cc
 * @brief handling of logging
 *
 * In this file the functions needed to log messages are contained.
 * Logging is possible to either syslog or files, depending on how the source has been configured
 */

#include "util.h"

namespace xmppd {

    logmessage::logmessage(logging &log_entity, int level) : log_entity(log_entity), level(level) {
    }

    logmessage::logmessage(const logmessage &orig) : log_entity(orig.log_entity), level(orig.level) {
    }

    logmessage::~logmessage() {
	const Glib::ustring &message = str();

	/* only log if something has been written */
	if (message != "")
	    log_entity.write(level, message);
    }

    logmessage &logmessage::ssl_errors() {
#ifdef USE_SSL
	unsigned long sslerr;

	while ((sslerr = ERR_get_error()) != 0)
	    this->operator<<("SSL/TLS: ") << ERR_error_string(sslerr, NULL);
#else
	this->operator<<("logmessage::ssl_errors() called but compiled " PACKAGE " without SSL/TLS support");
#endif

	return *this;
    }

    logging::logging(Glib::ustring ident) : identity(ident)
#ifndef USE_SYSLOG
	, logfile((ident + ".log").c_str()) 
#endif
    {
#ifdef USE_SYSLOG
	std::string logging_ident;
	try {
	    logging_ident = Glib::locale_from_utf8(identity);
	} catch (Glib::ConvertError) {
	    logging_ident = PACKAGE;
	}
	openlog(logging_ident.c_str(), LOG_PID, USE_SYSLOG);
#endif
    }

    logging::~logging() {
#ifdef USE_SYSLOG
	closelog();
#endif
    }

    logmessage logging::level(int level_to_use) {
	return logmessage(*this, level_to_use);
    }

    void logging::write(int level_to_use, Glib::ustring log_message) {
#ifdef USE_SYSLOG
	std::string message;
	try {
	    message = Glib::locale_from_utf8(log_message);
	} catch (Glib::ConvertError) {
	    message = "<Conversion Error, logging as UTF-8> ";
	    message += log_message;
	}
	syslog(level_to_use, "%s", message.c_str());
#else
	char timestamp[26];
	time_t now;

	time(&now);
	ctime_r(&now, timestamp);

	char *lf = strchr(timestamp, '\n');
	if (lf != NULL)
	    *lf = 0;

	logfile << timestamp << " [" << level_to_use << "] ";
	try {
	    logfile << (Glib::locale_from_utf8(log_message));
	} catch (Glib::ConvertError) {
	    logfile << "<Conversion Error, logging as UTF-8> " << log_message;
	}
	logfile << std::endl;
#endif
    }

    std::ostream &logmessage::operator<<(const char *text) {
	return static_cast<std::ostream&>(*this) << text;
    }

    std::ostream& logmessage::operator<<(const std::string& text) {
	return static_cast<std::ostream&>(*this) << text;
    }
}
