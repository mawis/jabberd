/*
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2007 Matthias Wimmer
 *
 * This file is part of jabberd14.
 *
 * This software is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

/**
 * @file mio_tls.cc
 * @brief MIO read/write functions to read/write on TLS encrypted sockets and handling for TLS in general (using the GNU TLS implementation)
 */

#include "jabberd.h"
#include <libtasn1.h>
#include <map>
#include <set>
#include <string>
#include <sstream>
#include <gcrypt.h>
#include <vector>
#include <list>
#include <iostream>

// Tell gcrypt that we are using libpth - had to move this to a plain C file
extern "C" void mio_tls_gcrypt_init(void);

extern const ASN1_ARRAY_TYPE subjectAltName_asn1_tab[];

/**
 * the credentials used by the server
 *
 * key is the virtual domain the credentials are used for ("*" for the default)
 * value the credentials to use
 */
std::map<std::string, gnutls_certificate_credentials_t> mio_tls_credentials;

/**
 * the protocols to use for a domain
 *
 * key is the virtual domain the credentials are used for ("*" for the default)
 * value the protocols to use
 */
std::map<std::string, int const*> mio_tls_protocols;

/**
 * the key exchange protocols to use for a domain
 *
 * key is the virtual domain the kx protocols are used for ("*" for the default)
 * value the kx protocols to use
 */
std::map<std::string, int const*> mio_tls_kx;

/**
 * the ciphers to use for a domain
 *
 * key is the virtual domain the ciphers are used for ("*" for the default)
 * value the ciphers to use
 */
std::map<std::string, int const*> mio_tls_ciphers;

/**
 * certificate types to use for a domain
 *
 * key is the virtual domain the ciphers are used for ("*" for the default)
 * value the certificate types to use
 */
std::map<std::string, int const*> mio_tls_certtypes;

/**
 * mac algorithms to use for a domain
 *
 * key is the virtual domain the mac algorithms are used for ("*" for the default)
 * value the mac algorithms to use
 */
std::map<std::string, int const*> mio_tls_mac;

/**
 * compression algorithms to use for a domain
 *
 * key is the virtual domain the compression algorithms are used for ("*" for the default)
 * value the compression algorithms to use
 */
std::map<std::string, int const*> mio_tls_compression;

/**
 * memory pool for allocation of priority arrays
 */
pool mio_tls_pool = NULL;

/**
 * tree of ASN1 structures
 */
ASN1_TYPE mio_tls_asn1_tree = ASN1_TYPE_EMPTY;

/**
 * close the TLS connection
 *
 * @param m the mio structure that contains the connection to close
 * @param close_read if the connection should be closed for reading as well
 */
static void mio_tls_close(mio m, bool close_read) {
    // sanity checks
    if (!m || !m->ssl)
	return;

    gnutls_bye(static_cast<gnutls_session_t>(m->ssl), close_read ? GNUTLS_SHUT_RDWR : GNUTLS_SHUT_WR);
    if (close_read) {
	close(m->fd);
    } else {
	shutdown(m->fd, SHUT_WR);
    }
}

/**
 * convert a string of protocol names to a zero terminated array for protocol constants
 *
 * @param p memory pool to use to allocate the result
 * @param protocols string containing the requested protocols
 * @return zero terminated array of protocols, NULL if nothing found
 */
static int const* mio_tls_compile_protocols(pool p, const std::string& protocols) {
    // sanity check
    if (p == NULL)
	return NULL;

    // prepare the data we will work on
    std::istringstream proto(protocols);
    std::vector<int> resultList;

    // convert string protocol by protocol
    while (proto) {
	std::string oneProtocol;
	proto >> oneProtocol;

	if (proto.fail())
	    break;

	if (oneProtocol == "SSL3") {
	    resultList.push_back(GNUTLS_SSL3);
	} else if (oneProtocol == "TLS1_0") {
	    resultList.push_back(GNUTLS_TLS1_0);
	} else if (oneProtocol == "TLS1_1") {
	    resultList.push_back(GNUTLS_TLS1_1);
#ifdef HAVE_TLS1_2
	} else if (oneProtocol == "TLS1_2") {
	    resultList.push_back(GNUTLS_TLS1_2);
#endif
	} else {
	    log_warn(NULL, "Found unknown protocol: %s", oneProtocol.c_str());
	}
    }

    // found any protocol?
    if (resultList.size() == 0)
	return NULL;

    // convert from a vector to a standard array
    int* result = static_cast<int*>(pmalloco(p, sizeof(int)*(resultList.size()+1)));
    for (int c=0; c<resultList.size(); c++) {
	result[c] = resultList[c];
    }
    result[resultList.size()] = 0;

    // return the result
    return result;
}

/**
 * convert a string of kx algorithms to a zero terminated array for kx constants
 *
 * @param p memory pool to use to allocate the result
 * @param kxAlgos string containing the requested kx algorithms
 * @return zero terminated array of algorithms, NULL if nothing found
 */
static int const* mio_tls_compile_kx(pool p, const std::string& kxAlgos) {
    // sanity check
    if (p == NULL)
	return NULL;

    // prepare the data we will work on
    std::istringstream kx(kxAlgos);
    std::vector<int> resultList;

    // convert string protocol by protocol
    while (kx) {
	std::string oneKx;
	kx >> oneKx;

	if (kx.fail())
	    break;

	if (oneKx == "RSA") {
	    resultList.push_back(GNUTLS_KX_RSA);
	} else if (oneKx == "DHE_DSS") {
	    resultList.push_back(GNUTLS_KX_DHE_DSS);
	} else if (oneKx == "DHE_RSA") {
	    resultList.push_back(GNUTLS_KX_DHE_RSA);
	} else if (oneKx == "ANON_DH") {
	    resultList.push_back(GNUTLS_KX_ANON_DH);
	} else if (oneKx == "SRP") {
	    resultList.push_back(GNUTLS_KX_SRP);
	} else if (oneKx == "RSA_EXPORT") {
	    resultList.push_back(GNUTLS_KX_RSA_EXPORT);
	} else if (oneKx == "SRP_RSA") {
	    resultList.push_back(GNUTLS_KX_SRP_RSA);
	} else if (oneKx == "SRP_DSS") {
	    resultList.push_back(GNUTLS_KX_SRP_DSS);
	} else if (oneKx == "PSK") {
	    resultList.push_back(GNUTLS_KX_PSK);
	} else if (oneKx == "DHE_PSK") {
	    resultList.push_back(GNUTLS_KX_DHE_PSK);
	} else {
	    log_warn(NULL, "Found unknown key exchange algorithm: %s", oneKx.c_str());
	}
    }

    // found any algorithms?
    if (resultList.size() == 0)
	return NULL;

    // convert from a vector to a standard array
    int* result = static_cast<int*>(pmalloco(p, sizeof(int)*(resultList.size()+1)));
    for (int c=0; c<resultList.size(); c++) {
	result[c] = resultList[c];
    }
    result[resultList.size()] = 0;

    // return the result
    return result;
}

/**
 * convert a string of ciphers to a zero terminated array for ciphers
 *
 * @param p memory pool to use to allocate the result
 * @param cipherAlgos string containing the requested ciphers
 * @return zero terminated array of ciphers, NULL if nothing found
 */
static int const* mio_tls_compile_ciphers(pool p, const std::string& cipherAlgos) {
    // sanity check
    if (p == NULL)
	return NULL;

    // prepare the data we will work on
    std::istringstream ciphers(cipherAlgos);
    std::vector<int> resultList;

    // convert string protocol by protocol
    while (ciphers) {
	std::string oneCipher;
	ciphers >> oneCipher;

	if (ciphers.fail())
	    break;

	if (oneCipher == "NULL") {
	    resultList.push_back(GNUTLS_CIPHER_NULL);
	} else if (oneCipher == "ARCFOUR_128") {
	    resultList.push_back(GNUTLS_CIPHER_ARCFOUR_128);
	} else if (oneCipher == "3DES_CBC") {
	    resultList.push_back(GNUTLS_CIPHER_3DES_CBC);
	} else if (oneCipher == "AES_128_CBC") {
	    resultList.push_back(GNUTLS_CIPHER_AES_128_CBC);
	} else if (oneCipher == "AES_256_CBC") {
	    resultList.push_back(GNUTLS_CIPHER_AES_256_CBC);
	} else if (oneCipher == "ARCFOUR_40") {
	    resultList.push_back(GNUTLS_CIPHER_ARCFOUR_40);
	} else if (oneCipher == "RC2_40_CBC") {
	    resultList.push_back(GNUTLS_CIPHER_RC2_40_CBC);
	} else if (oneCipher == "DES_CBC") {
	    resultList.push_back(GNUTLS_CIPHER_DES_CBC);
	} else {
	    log_warn(NULL, "Found unknown cipher algorithm: %s", oneCipher.c_str());
	}
    }

    // found any algorithms?
    if (resultList.size() == 0)
	return NULL;

    // convert from a vector to a standard array
    int* result = static_cast<int*>(pmalloco(p, sizeof(int)*(resultList.size()+1)));
    for (int c=0; c<resultList.size(); c++) {
	result[c] = resultList[c];
    }
    result[resultList.size()] = 0;

    // return the result
    return result;
}

/**
 * convert a string of certificate types to a zero terminated array for certificate types
 *
 * @param p memory pool to use to allocate the result
 * @param certTypes string containing the requested certificate types
 * @return zero terminated array of ciphers, NULL if nothing found
 */
static int const* mio_tls_compile_certtypes(pool p, const std::string& certTypes) {
    // sanity check
    if (p == NULL)
	return NULL;

    // prepare the data we will work on
    std::istringstream certs(certTypes);
    std::vector<int> resultList;

    // convert string protocol by protocol
    while (certs) {
	std::string oneCertType;
	certs >> oneCertType;

	if (certs.fail())
	    break;

	if (oneCertType == "X.509") {
	    resultList.push_back(GNUTLS_CRT_X509);
	} else if (oneCertType == "OpenPGP") {
	    resultList.push_back(GNUTLS_CRT_OPENPGP);
	} else {
	    log_warn(NULL, "Found unknown certificate type: %s", oneCertType.c_str());
	}
    }

    // found any algorithms?
    if (resultList.size() == 0)
	return NULL;

    // convert from a vector to a standard array
    int* result = static_cast<int*>(pmalloco(p, sizeof(int)*(resultList.size()+1)));
    for (int c=0; c<resultList.size(); c++) {
	result[c] = resultList[c];
    }
    result[resultList.size()] = 0;

    // return the result
    return result;
}

/**
 * convert a string of mac algorithms to a zero terminated array for mac algorithms
 *
 * @param p memory pool to use to allocate the result
 * @param macAlgos string containing the requested mac algorithms
 * @return zero terminated array of mac algorithms, NULL if nothing found
 */
static int const* mio_tls_compile_mac(pool p, const std::string& macAlgos) {
    // sanity check
    if (p == NULL)
	return NULL;

    // prepare the data we will work on
    std::istringstream macs(macAlgos);
    std::vector<int> resultList;

    // convert string protocol by protocol
    while (macs) {
	std::string oneMac;
	macs >> oneMac;

	if (macs.fail())
	    break;

	if (oneMac == "NULL") {
	    resultList.push_back(GNUTLS_MAC_NULL);
	} else if (oneMac == "MD5") {
	    resultList.push_back(GNUTLS_MAC_MD5);
	} else if (oneMac == "SHA1") {
	    resultList.push_back(GNUTLS_MAC_SHA1);
	} else if (oneMac == "RMD160") {
	    resultList.push_back(GNUTLS_MAC_RMD160);
	} else if (oneMac == "MD2") {
	    resultList.push_back(GNUTLS_MAC_MD2);
	} else {
	    log_warn(NULL, "Found unknown MAC algorithm: %s", oneMac.c_str());
	}
    }

    // found any algorithms?
    if (resultList.size() == 0)
	return NULL;

    // convert from a vector to a standard array
    int* result = static_cast<int*>(pmalloco(p, sizeof(int)*(resultList.size()+1)));
    for (int c=0; c<resultList.size(); c++) {
	result[c] = resultList[c];
    }
    result[resultList.size()] = 0;

    // return the result
    return result;
}

/**
 * convert a string of compression algorithms to a zero terminated array for compression algorithms
 *
 * @param p memory pool to use to allocate the result
 * @param compressionAlgos string containing the requested compression algorithms
 * @return zero terminated array of compression algorithms, NULL if nothing found
 */
static int const* mio_tls_compile_compression(pool p, const std::string& compressionAlgos) {
    // sanity check
    if (p == NULL)
	return NULL;

    // prepare the data we will work on
    std::istringstream compressions(compressionAlgos);
    std::vector<int> resultList;

    // convert string protocol by protocol
    while (compressions) {
	std::string oneCompression;
	compressions >> oneCompression;

	if (compressions.fail())
	    break;

	if (oneCompression == "NULL") {
	    resultList.push_back(GNUTLS_COMP_NULL);
	} else if (oneCompression == "DEFLATE") {
	    resultList.push_back(GNUTLS_COMP_DEFLATE);
#ifdef HAVE_GNUTLS_EXTRA
	} else if (oneCompression == "LZO") {
	    resultList.push_back(GNUTLS_COMP_LZO);
#endif
	} else {
	    log_warn(NULL, "Found unknown compression algorithm: %s", oneCompression.c_str());
	}
    }

    // found any algorithms?
    if (resultList.size() == 0)
	return NULL;

    // convert from a vector to a standard array
    int* result = static_cast<int*>(pmalloco(p, sizeof(int)*(resultList.size()+1)));
    for (int c=0; c<resultList.size(); c++) {
	result[c] = resultList[c];
    }
    result[resultList.size()] = 0;

    // return the result
    return result;
}

/**
 * process a configuration element configuring a set of credentials in the configuration file
 *
 * @param x the xmlnode containing the set
 * @param default_cacertfile file containing ca certificates to use if the set does not contain its own definition
 * @param mio_tls_dh_params DH params to use (for performance reasons the same params are used for all sets
 * @param crl_files_pem the CRL files in PEM format to load
 * @param crl_files_der the CRL files in DER format to load
 */
static void mio_tls_process_credentials(xmlnode x, const std::list<std::string>& default_cacertfile_pem, const std::list<std::string>& default_cacertfile_der, gnutls_dh_params_t mio_tls_dh_params, const std::list<std::string>& crl_files_pem, const std::list<std::string>& crl_files_der) {
    std::set<std::string> domains;
    int ret = 0;
    bool loaded_cacerts = false;
    std::string protocols;
    std::string kx;
    std::string ciphers;
    std::string certtypes = "X.509";
    std::string mac = "SHA1";
    std::string compression = "NULL";

    // prepare the credentials
    gnutls_certificate_credentials_t current_credentials = NULL;
    ret = gnutls_certificate_allocate_credentials (&current_credentials);
    if (ret < 0) {
	log_error(NULL, "Error initializing credentials: %s", gnutls_strerror(ret));
	return;
    }

    // iterate the child elements
    for (xmlnode cur = xmlnode_get_firstchild(x); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	// we only process elements in the NS_JABBERD_CONFIGFILE namespace
	if (j_strcmp(xmlnode_get_namespace(cur), NS_JABBERD_CONFIGFILE) != 0) {
	    continue;
	}

	// is it a default declaration?
	if (j_strcmp(xmlnode_get_localname(cur), "default") == 0) {
	    domains.insert("*");
	    continue;
	}

	// is it a domain declaration?
	if (j_strcmp(xmlnode_get_localname(cur), "domain") == 0) {
	    char const *const domain = xmlnode_get_data(cur);

	    // check that we had a domain name in the configuration
	    if (domain == NULL) {
		log_warn(NULL, "Initializing TLS subsystem: <domain/> element inside the TLS configuration, that does not contain a domain name.");
		continue;
	    }

	    // add it to the set for domains for which we have to add the credentials after we loaded them
	    domains.insert(domain);
	    continue;
	}

	// a X.509 certificate in PEM format?
	if (j_strcmp(xmlnode_get_localname(cur), "pem") == 0) {
	    char const *const pubfile = xmlnode_get_data(cur);
	    char const * privfile = xmlnode_get_attrib_ns(cur, "private-key", NULL);

	    // there needs to be a filename for the public key
	    if (pubfile == NULL) {
		log_warn(NULL, "Initializing TLS subsystem: <pem/> element inside the TLS configuration, that does not contain a file-name.");
		continue;
	    }

	    // if there is no filename for the private key, use the same as for the public key (file containing both keys)
	    if (privfile == NULL)
		privfile = pubfile;

	    // load the X.509 certificate
	    ret = gnutls_certificate_set_x509_key_file(current_credentials, pubfile, privfile, GNUTLS_X509_FMT_PEM);
	    if (ret < 0) {
		log_error(NULL, "Error loading X.509 certificate (PEM) pub=%s/priv=%s: %s", pubfile, privfile, gnutls_strerror(ret));
		continue;
	    }

	    continue;
	}

	// a X.509 certificate in DER format?
	if (j_strcmp(xmlnode_get_localname(cur), "der") == 0) {
	    char const *const pubfile = xmlnode_get_data(cur);
	    char const * privfile = xmlnode_get_attrib_ns(cur, "private-key", NULL);

	    // there needs to be a filename for the public key
	    if (pubfile == NULL) {
		log_warn(NULL, "Initializing TLS subsystem: <der/> element inside the TLS configuration, that does not contain a file-name.");
		continue;
	    }

	    // if there is no filename for the private key, use the same as for the public key (file containing both keys)
	    if (privfile == NULL)
		privfile = pubfile;

	    // load the X.509 certificate
	    ret = gnutls_certificate_set_x509_key_file(current_credentials, pubfile, privfile, GNUTLS_X509_FMT_DER);
	    if (ret < 0) {
		log_error(NULL, "Error loading X.509 certificate (DER) pub=%s/priv=%s: %s", pubfile, privfile, gnutls_strerror(ret));
		continue;
	    }

	    continue;
	}

	// load a certification authority certificate
	if (j_strcmp(xmlnode_get_localname(cur), "ca") == 0) {
	    bool format_der = j_strcmp(xmlnode_get_attrib_ns(cur, "type", NULL), "der") == 0;
	    char const *const file = xmlnode_get_data(cur);

	    // is there a filename?
	    if (file == NULL) {
		log_warn(NULL, "Initializing TLS subsystem: <ca/> element inside the TLS configuration, that does not contain a file-name.");
		continue;
	    }

	    // load the CA's certificate
	    ret = gnutls_certificate_set_x509_trust_file(current_credentials, file, format_der ? GNUTLS_X509_FMT_DER : GNUTLS_X509_FMT_PEM);
	    if (ret < 0) {
		log_error(NULL, "Error loading certificate of CA (%s) %s: %s", format_der ? "DER" : "PEM", file, gnutls_strerror(ret));
		continue;
	    }

	    // we have had a CA certificate, we do not need to load the defaults
	    loaded_cacerts = true;

	    continue;
	}

	// load an OpenPGP key
	if (j_strcmp(xmlnode_get_localname(cur), "openpgp") == 0) {
	    char const *const pubfile = xmlnode_get_data(cur);
	    char const *const privfile = xmlnode_get_attrib_ns(cur, "private-key", NULL);

	    // ensure that we have two filenames
	    if (pubfile == NULL) {
		log_warn(NULL, "Initializing TLS subsystem: <openpgp/> element inside the TLS configuration, that does not contain a file-name.");
		continue;
	    }
	    if (privfile == NULL) {
		log_warn(NULL, "Initializing TLS subsystem: <openpgp/> element inside the TLS configuration, that does not contain a private-key file-name.");
		continue;
	    }

	    // load OpenPGP key/certificate
	    ret = gnutls_certificate_set_openpgp_key_file(current_credentials, pubfile, privfile);
	    if (ret < 0) {
		log_error(NULL, "Error loading OpenPGP key pub=%s/priv=%s: %s", pubfile, privfile, gnutls_strerror(ret));
		continue;
	    }

	    continue;
	}

	// load OpenPGP keyring
	if (j_strcmp(xmlnode_get_localname(cur), "keyring") == 0) {
	    char const *const file = xmlnode_get_data(cur);

	    if (file == NULL) {
		log_warn(NULL, "Initializing TLS subsystem: <keyring/> element inside the TLS configuration, that does not contain a file-name.");
		continue;
	    }

	    // load the OpenPGP keyring
	    ret = gnutls_certificate_set_openpgp_keyring_file(current_credentials, file);
	    if (ret < 0) {
		log_error(NULL, "Error loading OpenPGP keyring %s: %s", file, gnutls_strerror(ret));
		continue;
	    }

	    continue;
	}

	// load GnuPG trustdb
	if (j_strcmp(xmlnode_get_localname(cur), "trustdb") == 0) {
	    char const *const file = xmlnode_get_data(cur);

	    if (file == NULL) {
		log_warn(NULL, "Initializing TLS subsystem: <trustdb/> element inside the TLS configuration, that does not contain a file-name.");
		continue;
	    }

	    // load the GnuPG trustdb
	    ret = gnutls_certificate_set_openpgp_trustdb(current_credentials, file);
	    if (ret < 0) {
		log_error(NULL, "Error loading GnuPG trustdb %s: %s", file, gnutls_strerror(ret));
		continue;
	    }
	}

	// setup protocols to use
	if (j_strcmp(xmlnode_get_localname(cur), "protocols") == 0) {
	    char const *const protocols_data = xmlnode_get_data(cur);
	    if (protocols_data != NULL)
		protocols = protocols_data;
	    continue;
	}

	// setup key exchange protocols to use
	if (j_strcmp(xmlnode_get_localname(cur), "kx") == 0) {
	    char const *const kx_data = xmlnode_get_data(cur);
	    if (kx_data != NULL)
		kx = kx_data;
	    continue;
	}

	// setup ciphers to use
	if (j_strcmp(xmlnode_get_localname(cur), "ciphers") == 0) {
	    char const *const ciphers_data = xmlnode_get_data(cur);
	    if (ciphers_data != NULL)
		ciphers = ciphers_data;
	    continue;
	}

	// setup certificate types to use
	if (j_strcmp(xmlnode_get_localname(cur), "certtypes") == 0) {
	    char const *const certtypes_data = xmlnode_get_data(cur);
	    if (certtypes_data != NULL)
		certtypes = certtypes_data;
	    continue;
	}

	// setup MAC algorithms to use
	if (j_strcmp(xmlnode_get_localname(cur), "mac") == 0) {
	    char const *const mac_data = xmlnode_get_data(cur);
	    if (mac_data != NULL)
		mac = mac_data;
	    continue;
	}

	// setup compression algorithms to use
	if (j_strcmp(xmlnode_get_localname(cur), "compression") == 0) {
	    char const *const compression_data = xmlnode_get_data(cur);
	    if (compression_data != NULL)
		compression = compression_data;
	    continue;
	}
    }

    /* set the DH params for this certificate */
    gnutls_certificate_set_dh_params(current_credentials, mio_tls_dh_params);

    // load CRL files
    std::list<std::string>::const_iterator crl_p;
    for (crl_p=crl_files_pem.begin(); crl_p!=crl_files_pem.end(); ++crl_p) {
	char const* file_to_load = crl_p->c_str();

	ret = gnutls_certificate_set_x509_crl_file(current_credentials, file_to_load, GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
	    log_error(NULL, "Error loading CRL file %s (PEM): %s", file_to_load, gnutls_strerror(ret));
	}
    }
    for (crl_p=crl_files_der.begin(); crl_p!=crl_files_der.end(); ++crl_p) {
	char const* file_to_load = crl_p->c_str();

	ret = gnutls_certificate_set_x509_crl_file(current_credentials, file_to_load, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
	    log_error(NULL, "Error loading CRL file %s (DER): %s", file_to_load, gnutls_strerror(ret));
	}
    }

    // loaded any CA certificate? if not load the defaults
    if (!loaded_cacerts) {
	std::list<std::string>::const_iterator p;
	for (p=default_cacertfile_pem.begin(); p!=default_cacertfile_pem.end(); ++p) {
	    ret = gnutls_certificate_set_x509_trust_file(current_credentials, p->c_str(), GNUTLS_X509_FMT_PEM);
	    if (ret < 0) {
		log_error(NULL, "Error loading default CA certificate %s (PEM): %s", p->c_str(), gnutls_strerror(ret));
	    }
	}
	for (p=default_cacertfile_der.begin(); p!=default_cacertfile_der.end(); ++p) {
	    ret = gnutls_certificate_set_x509_trust_file(current_credentials, p->c_str(), GNUTLS_X509_FMT_DER);
	    if (ret < 0) {
		log_error(NULL, "Error loading default CA certificate %s (DER): %s", p->c_str(), gnutls_strerror(ret));
	    }
	}
    }

    // make the credentials active for the selected domains
    bool credentials_used = false;
    std::set<std::string>::const_iterator p;
    for (p = domains.begin(); p!= domains.end(); ++p) {
	if (mio_tls_credentials.find(*p) != mio_tls_credentials.end()) {
	    log_warn(NULL, "Redefinition of TLS credentials for domain %s. Ignoring redefinition.", p->c_str());
	    continue;
	}

	credentials_used = true;
	mio_tls_credentials[*p] = current_credentials;
	if (protocols != "" && mio_tls_protocols.find(*p) == mio_tls_protocols.end()) {
	    int const* compiled_protocols = mio_tls_compile_protocols(mio_tls_pool, protocols);
	    if (compiled_protocols != NULL) {
		mio_tls_protocols[*p] = compiled_protocols;
	    }
	}
	if (kx != "" && mio_tls_kx.find(*p) == mio_tls_kx.end()) {
	    int const* compiled_kx = mio_tls_compile_kx(mio_tls_pool, kx);
	    if (compiled_kx != NULL) {
		mio_tls_kx[*p] = compiled_kx;
	    }
	}
	if (ciphers != "" && mio_tls_ciphers.find(*p) == mio_tls_ciphers.end()) {
	    int const* compiled_ciphers = mio_tls_compile_ciphers(mio_tls_pool, ciphers);
	    if (compiled_ciphers != NULL) {
		mio_tls_ciphers[*p] = compiled_ciphers;
	    }
	}
	if (certtypes != "" && mio_tls_certtypes.find(*p) == mio_tls_certtypes.end()) {
	    int const* compiled_certtypes = mio_tls_compile_certtypes(mio_tls_pool, certtypes);
	    if (compiled_certtypes != NULL) {
		mio_tls_certtypes[*p] = compiled_certtypes;
	    }
	}
	if (mac != "" && mio_tls_mac.find(*p) == mio_tls_mac.end()) {
	    int const* compiled_mac = mio_tls_compile_mac(mio_tls_pool, mac);
	    if (compiled_mac != NULL) {
		mio_tls_mac[*p] = compiled_mac;
	    }
	}
	if (compression != "" && mio_tls_compression.find(*p) == mio_tls_compression.end()) {
	    int const* compiled_compression = mio_tls_compile_compression(mio_tls_pool, compression);
	    if (compiled_compression != NULL) {
		mio_tls_compression[*p] = compiled_compression;
	    }
	}
    }

    // check if the credentials are used for any domain
    if (!credentials_used) {
	log_warn(NULL, "Found credentials definition, that is not used for any domain.");
	gnutls_certificate_free_credentials(current_credentials);
    }
}

/**
 * process a &lt;key/&gt; configuration element
 *
 * @param x the configuration element
 * @param default_cacertfile_pem list of PEM files containing the CA certificates to use
 * @param default_cacertfile_der list of DER files containing the CA certificates to use
 * @param mio_tls_dh_params the Diffie-Hellman parameters to be used
 */
static void mio_tls_process_key(xmlnode x, const std::list<std::string>& default_cacertfile_pem, const std::list<std::string>& default_cacertfile_der, gnutls_dh_params_t mio_tls_dh_params) {
    char *file_to_use = xmlnode_get_data(x);
    char *key_type = xmlnode_get_attrib_ns(x, "type", NULL);
    char *id = xmlnode_get_attrib_ns(x, "id", NULL);
    char *private_key_file = xmlnode_get_attrib_ns(x, "private-key", NULL);
    char *no_ssl_v2 = xmlnode_get_attrib_ns(x, "no-ssl-v2", NULL);
    char *no_ssl_v3 = xmlnode_get_attrib_ns(x, "no-ssl-v3", NULL);
    char *no_tls_v1 = xmlnode_get_attrib_ns(x, "no-tls-v1", NULL);
    char *ciphers = xmlnode_get_attrib_ns(x, "ciphers", NULL);
    gnutls_x509_crt_fmt_t certificate_type = GNUTLS_X509_FMT_PEM;
    int ret = 0;

    /* no id attribute? first try ip instead, else default key */
    if (id == NULL) {
	id = xmlnode_get_attrib_ns(x, "ip", NULL);
	if (id == NULL) {
	    id = "*";
	}
    }

    /* no public key file? */
    if (file_to_use == NULL) {
	log_notice(id, "Cannot load X.509 certificate: no file specified.");
	return;
    }

    /* PEM or DER format? */
    if (j_strcmp(xmlnode_get_attrib_ns(x, "type", NULL), "der") == 0) {
	certificate_type = GNUTLS_X509_FMT_DER;
    }

    /* check old attributes not supported anymore */
    if (no_ssl_v2 != NULL || no_ssl_v3 != NULL || no_tls_v1 != NULL || ciphers != NULL) {
	log_notice(id, "Warning: ignoring a attribute when loading X.509 certificate. Not supported anymore are: no-ssl-v2, no-ssl-v3, no-tls-v1 and ciphers");
    }

    /* no special private key file? use the same as the public key file */
    if (private_key_file == NULL) {
	private_key_file = file_to_use;
    }

    /* load the keys */
    gnutls_certificate_credentials_t current_credentials = NULL;
    ret = gnutls_certificate_allocate_credentials (&current_credentials);
    if (ret < 0) {
	log_error(id, "Error initializing credentials: %s", gnutls_strerror(ret));
	return;
    }
    ret = gnutls_certificate_set_x509_key_file(current_credentials, file_to_use, private_key_file, certificate_type);
    if (ret < 0) {
	log_error(id, "Error loading key file cert=%s/priv=%s: %s", file_to_use, private_key_file, gnutls_strerror(ret));
	gnutls_certificate_free_credentials(current_credentials);
	return;
    }

    /* load CA certificates */
    std::list<std::string>::const_iterator p;
    for (p=default_cacertfile_pem.begin(); p!=default_cacertfile_pem.end(); ++p) {
	ret = gnutls_certificate_set_x509_trust_file(current_credentials, p->c_str(), GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
	    log_error(id, "Error loading CA certificates %s (PEM): %s", p->c_str(), gnutls_strerror(ret));
	}
    }
    for (p=default_cacertfile_der.begin(); p!=default_cacertfile_der.end(); ++p) {
	ret = gnutls_certificate_set_x509_trust_file(current_credentials, p->c_str(), GNUTLS_X509_FMT_DER);
	if (ret < 0) {
	    log_error(id, "Error loading CA certificates %s (DER): %s", p->c_str(), gnutls_strerror(ret));
	}
    }

    /* set the DH params for this certificate */
    gnutls_certificate_set_dh_params(current_credentials, mio_tls_dh_params);

    /* store the loaded certificate */
    mio_tls_credentials[id] = current_credentials;
}

/**
 * early initiatizations for GnuTLS
 *
 * This has to be called as soon as possible after application startup
 *
 * @return true on success, false on failure
 */
bool mio_tls_early_init() {
    // prepare gcrypt with libpth
    mio_tls_gcrypt_init();

    /* initialize the GNU TLS library */
    int ret = gnutls_global_init();
    if (ret != 0) {
	std::cerr << "Error initializing GnuTLS library: " << gnutls_strerror(ret) << std::endl;
	return false;
    }

#ifdef HAVE_GNUTLS_EXTRA
    /* initialize the GnuTLS extra library */
    ret = gnutls_global_init_extra();
    if (ret != 0) {
	std::cerr << "Error initializing GnuTLS-extra library: " << gnutls_strerror(ret) << std::endl;
	return false;
    }
#endif

    /* load asn1 tree to be used by libtasn1 */
    ret = asn1_array2tree(subjectAltName_asn1_tab, &mio_tls_asn1_tree, NULL);
    if (ret != ASN1_SUCCESS) {
	std::cerr << "Error preparing the libtasn1 library: " << libtasn1_strerror(ret) << std::endl;
	return false;
	/* XXX we have to delete the structure on shutdown using asn1_delete_structure(&mio_tls_asn1_tree) */
    }

    return true;
}

/**
 * initialize the mio SSL/TLS module using the GNU TLS library
 *
 * @param x xmlnode containing the configuration information (the io/tls element)
 */
void mio_ssl_init(xmlnode x) {
    xmlnode cur = NULL;
    int ret = 0;
    static gnutls_dh_params_t mio_tls_dh_params;
    xht namespaces = NULL;

    log_debug2(ZONE, LOGT_IO, "MIO TLS init (GNU TLS)");

    namespaces = xhash_new(3);
    xhash_put(namespaces, "", const_cast<char*>(NS_JABBERD_CONFIGFILE));

    /* create memory pool */
    mio_tls_pool = pool_new();

    /* find the default CA certificates file */
    std::list<std::string> default_cacertfile_pem;
    std::list<std::string> default_cacertfile_der;
    std::string dhparams;
    std::list<std::string> crl_files_pem;
    std::list<std::string> crl_files_der;
    bool dhparams_der = false;
    for (cur = xmlnode_get_firstchild(x); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	if (cur->type != NTYPE_TAG) {
	    continue;
	}

	if (j_strcmp(xmlnode_get_namespace(cur), NS_JABBERD_CONFIGFILE) != 0) {
	    continue;
	}

	if (j_strcmp(xmlnode_get_localname(cur), "cacertfile") == 0) {
	    char const* const cacertfile_data = xmlnode_get_data(cur);

	    if (cacertfile_data != NULL) {
		bool der_format = j_strcmp(xmlnode_get_attrib_ns(cur, "type", NULL), "der") == 0;

		if (der_format) {
		    default_cacertfile_der.push_back(cacertfile_data);
		} else {
		    default_cacertfile_pem.push_back(cacertfile_data);
		}
	    }

	    continue;
	}

	if (j_strcmp(xmlnode_get_localname(cur), "dhparams") == 0) {
	    char const *const dhparams_data = xmlnode_get_data(cur);

	    if (dhparams_data != NULL) {
		dhparams = dhparams_data;
		dhparams_der = j_strcmp(xmlnode_get_attrib_ns(cur, "type", NULL), "der") == 0;
	    }

	    continue;
	}

	if (j_strcmp(xmlnode_get_localname(cur), "crlfile") == 0) {
	    char const *const crlfile_data = xmlnode_get_data(cur);
	    char const *const crlfile_type = xmlnode_get_attrib_ns(cur, "type", NULL);

	    if (crlfile_data != NULL) {
		if (j_strcmp(crlfile_type, "der") == 0) {
		    crl_files_der.push_back(crlfile_data);
		} else {
		    crl_files_pem.push_back(crlfile_data);
		}
	    }

	    continue;
	}
    }

    /* create DH parameters */
    ret = gnutls_dh_params_init(&mio_tls_dh_params);
    if (ret < 0) {
	log_error(ZONE, "Error initializing DH params: %s", gnutls_strerror(ret));
    }
    bool dhparams_set = false;
    if (dhparams != "") {
	int filehandle = open(dhparams.c_str(), O_RDONLY);
	if (filehandle == -1) {
	    log_warn(NULL, "Cannot open %s for reading dhparams: %s", dhparams.c_str(), strerror(errno));
	} else {
	    std::string filecontent;
	    char buffer[1024];
	    do {
		ret = pth_read(filehandle, buffer, sizeof(buffer));
		if (ret > 0) {
		    filecontent += std::string(buffer, ret);
		}
	    } while (ret > 0);
	    close(filehandle);

	    gnutls_datum_t pkcs3_data;
	    pkcs3_data.size = filecontent.length();
	    pkcs3_data.data = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(filecontent.c_str()));
	    ret = gnutls_dh_params_import_pkcs3(mio_tls_dh_params, &pkcs3_data, dhparams_der ? GNUTLS_X509_FMT_DER : GNUTLS_X509_FMT_PEM);
	    if (ret > 0) {
		log_warn(NULL, "Error importing dhparams (%s) %s: %s", dhparams_der ? "DER" : "PEM", dhparams.c_str(), gnutls_strerror(ret));
	    } else {
		dhparams_set = true;
	    }
	}
    }
    if (!dhparams_set) {
	ret = gnutls_dh_params_generate2(mio_tls_dh_params, 1024);
	if (ret < 0) {
	    log_error(ZONE, "Error generating DH params: %s", gnutls_strerror(ret));
	}
    }

    /* load the certificates */
    for (cur = xmlnode_get_firstchild(x); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	if (cur->type != NTYPE_TAG) {
	    continue;
	}

	/* which element did we get? */
	if (j_strcmp(xmlnode_get_localname(cur), "credentials") == 0 && j_strcmp(xmlnode_get_namespace(cur), NS_JABBERD_CONFIGFILE) == 0) {
	    /* it's a credentials group (new format) */
	    mio_tls_process_credentials(cur, default_cacertfile_pem, default_cacertfile_der, mio_tls_dh_params, crl_files_pem, crl_files_der);
	} else if (j_strcmp(xmlnode_get_localname(cur), "key") == 0 && j_strcmp(xmlnode_get_namespace(cur), NS_JABBERD_CONFIGFILE) == 0) {
	    /* it's a key - old format */
	    mio_tls_process_key(cur, default_cacertfile_pem, default_cacertfile_der, mio_tls_dh_params);
	}
    }

    xhash_free(namespaces);
    namespaces = NULL;
}

void _mio_ssl_cleanup(void *arg) {
    gnutls_session_t session = (gnutls_session_t)arg;

    log_debug2(ZONE, LOGT_IO, "GNU TLS session cleanup for %X", session);
    gnutls_deinit(session);
}

/**
 * read data from a socket, that is TLS protected
 *
 * The m->flags.recall_read_when_readable and m->flags.recall_read_when_writeable is updated by this function.
 *
 * @param m the ::mio where data might be available
 * @param buf where to write the written data to
 * @param count how many bytes should be read at most
 * @return 0 < ret < count: ret bytes read and no more bytes to read; ret = count: ret bytes read, possibly more bytes to read; ret = 0: currently nothing to read; ret < 0: non-recoverable error or connection closed
 */
ssize_t _mio_ssl_read(mio m, void *buf, size_t count) {
    int read_return = 0;

    /* sanity checks */
    if (count <= 0 || buf == NULL || m == NULL) {
	return count == 0 ? 0 : -1;
    }

    log_debug2(ZONE, LOGT_IO, "Trying to read up to %i B from socket %i using GnuTLS", count, m->fd);

    /* reset flags */
    m->flags.recall_read_when_readable = 0;
    m->flags.recall_read_when_writeable = 0;

    /* trying to read */
    read_return = gnutls_record_recv(static_cast<gnutls_session_t>(m->ssl), (char*)buf, count);

    if (read_return > 0) {
	log_debug2(ZONE, LOGT_IO, "Read %i B on socket %i", read_return, m->fd);
	return read_return;
    }
    if (read_return == GNUTLS_E_INTERRUPTED || read_return == GNUTLS_E_AGAIN) {
	if (gnutls_record_get_direction(static_cast<gnutls_session_t>(m->ssl)) == 0) {
	    m->flags.recall_read_when_readable = 1;
	} else {
	    m->flags.recall_read_when_writeable = 1;
	}
	return 0;
    }
    if (read_return == GNUTLS_E_FATAL_ALERT_RECEIVED) {
	log_notice(NULL, "Received fatal TLS alert on socket %i: %s", m->fd, gnutls_alert_get_name(gnutls_alert_get(static_cast<gnutls_session_t>(m->ssl))));
    } else if (read_return == GNUTLS_E_WARNING_ALERT_RECEIVED) {
	log_debug2(ZONE, LOGT_IO, "Received warning TLS alert on socket %i: %s", m->fd, gnutls_alert_get_name(gnutls_alert_get(static_cast<gnutls_session_t>(m->ssl))));
    }

    log_debug2(ZONE, LOGT_IO, "Error case after gnutls_record_recv(): %s", gnutls_strerror(read_return));

    return -1;
}

/**
 * write data to a socket, that is TLS protected
 *
 * The m->flags.recall_write_when_readable and m->flags.recall_write_when_writeable is updated by this function.
 *
 * @param m the ::mio where writing is possible
 * @param buf data that should be written
 * @param count how many bytes should be written at most
 * @return ret > 0: ret bytes written; ret == 0: no bytes could be written; ret < 0: non-recoverable error or connection closed
 */
ssize_t _mio_ssl_write(mio m, const void *buf, size_t count) {
    int write_return = 0;

    /* sanity checks */
    if (count <= 0 || buf == NULL || m == NULL) {
	return count == 0 ? 0 : -1;
    }

    log_debug2(ZONE, LOGT_IO, "Trying to write up to %i B to socket %i using GnuTLS", count, m->fd);

    /* reset flags */
    m->flags.recall_write_when_readable = 0;
    m->flags.recall_write_when_writeable = 0;

    /* trying to write data */
    write_return = gnutls_record_send(static_cast<gnutls_session_t>(m->ssl), buf, count);

    if (write_return > 0) {
	log_debug2(ZONE, LOGT_IO, "Wrote %i B on socket %i", write_return, m->fd);
	return write_return;
    }
    if (write_return == GNUTLS_E_INTERRUPTED || write_return == GNUTLS_E_AGAIN) {
	if (gnutls_record_get_direction(static_cast<gnutls_session_t>(m->ssl)) == 0) {
	    m->flags.recall_write_when_readable = 1;
	} else {
	    m->flags.recall_write_when_writeable = 1;
	}
	return 0;
    }
    if (write_return == GNUTLS_E_FATAL_ALERT_RECEIVED) {
	log_notice(NULL, "Received fatal TLS alert on socket %i: %s", m->fd, gnutls_alert_get_name(gnutls_alert_get(static_cast<gnutls_session_t>(m->ssl))));
    } else if (write_return == GNUTLS_E_WARNING_ALERT_RECEIVED) {
	log_debug2(ZONE, LOGT_IO, "Received warning TLS alert on socket %i: %s", m->fd, gnutls_alert_get_name(gnutls_alert_get(static_cast<gnutls_session_t>(m->ssl))));
    }

    log_debug2(ZONE, LOGT_IO, "Error case after gnutls_record_send(): %s", gnutls_strerror(write_return));

    return -1;
}

/**
 * continue a TLS handshake (as server side) when new data is available or data can be written now
 *
 * @param m the mio of the socket
 * @return -1 on error, 0 if handshake did not complete yet, 1 on success
 */
int _mio_tls_cont_handshake_server(mio m) {
    int ret = 0;

    /* we are recalled, if neccessary we set the flags again */
    m->flags.recall_handshake_when_readable = 0;
    m->flags.recall_handshake_when_writeable = 0;

    /* continue the handshake */
    ret = gnutls_handshake(static_cast<gnutls_session_t>(m->ssl));
    if (ret >= 0) {
	/* reset the handler for handshake */
	m->mh->handshake = NULL;
	log_debug2(ZONE, LOGT_IO, "TLS handshake finished for fd #%i", m->fd);
	return 1;
    } else if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
	if (gnutls_record_get_direction(static_cast<gnutls_session_t>(m->ssl)) == 0) {
	    log_debug2(ZONE, LOGT_IO, "TLS layer needs to read data to complete handshake (fd #%i)", m->fd);
	    m->flags.recall_handshake_when_readable = 1;
	} else {
	    log_debug2(ZONE, LOGT_IO, "TLS layer needs to write data to complete handshake (fd #%i)", m->fd);
	    m->flags.recall_handshake_when_writeable = 1;
	}
	return 0;
    } else {
	log_debug2(ZONE, LOGT_IO, "TLS handshake failed for fd #%i: %s", m->fd, gnutls_strerror(ret));
	return -1;
    }
}

/**
 * accepted a new incoming connection, where we have to start the TLS layer without a STARTTLS command, e.g. on port 5223
 *
 * @param m the mio of the listening socket
 * @return -1 on error, 0 if the handshake has not yet finished, 1 on success
 */
int _mio_ssl_accepted(mio m) {
    return mio_ssl_starttls(m, 0, m->our_ip) == 0 ? 1 : -1;
}

/**
 * check if a connection is encrypted
 *
 * @param m the connection
 * @return 0 if the connection is unprotected, 1 if the connection is integrity protected, >1 if the connection is encrypted
 */
int mio_is_encrypted(mio m) {
    return m->ssl == NULL ? 0 : 8*gnutls_cipher_get_key_size(gnutls_cipher_get(static_cast<gnutls_session_t>(m->ssl)));
}

/**
 * check if it would be possible to start TLS on a connection
 *
 * @param m the connection
 * @param identity our own identity (check if certificate is present)
 * @return 0 if it is impossible, 1 if it is possible
 */
int mio_ssl_starttls_possible(mio m, const char* identity) {
    /* if the connection is already TLS protected, we cannot start a second TLS layer */
    if (m->ssl != NULL) {
	return 0;
    }

    /* check if we have a certificate for this domain */
    if (identity != NULL && mio_tls_credentials.find(identity) != mio_tls_credentials.end()) {
	return 1;
    }

    /* or there might be a default certificate */
    if (mio_tls_credentials.find("*") != mio_tls_credentials.end()) {
	return 1;
    }

    /* no certificate credentials for this identity available */
    return 0;
}

/**
 * start a TLS layer on a connection and set the appropriate mio handlers for SSL/TLS
 *
 * @param m the connection on which the TLS layer should be established
 * @param originator 1 if this side is the originating side, 0 else
 * @param identity our own identity (selector for the used certificate)
 * @return 0 on success, non-zero on failure
 */
int mio_ssl_starttls(mio m, int originator, const char* identity) {
    gnutls_session_t session = NULL;
    gnutls_certificate_credentials_t used_credentials = NULL;
    int ret = 0;

    /* sanity check */
    if (m == NULL)
	return 1;

    /* only start TLS on a connection once */
    if (m->ssl != NULL) {
	log_debug2(ZONE, LOGT_EXECFLOW|LOGT_IO, "cannot start TLS layer on an already encrapted socket (mio=%X)", m);
	return 1;
    }

    /* get the right credentials */
    if (identity != NULL && mio_tls_credentials.find(identity) != mio_tls_credentials.end()) {
	used_credentials = mio_tls_credentials[identity];
    } else {
	used_credentials = mio_tls_credentials["*"];
    }
    if (used_credentials == NULL) {
	log_error(identity, "Cannot start TLS layer for %s - no credentials available, even no default ones", identity);
	return 1;
    }

    log_debug2(ZONE, LOGT_IO, "Establishing TLS layer for %s connection (we=%s, peer=%s, identity=%s)", originator ? "outgoing" : "incoming", m->our_ip, m->peer_ip, identity);

    /* GNU TLS setup for this connection */
    ret = gnutls_init(&session, originator ? GNUTLS_CLIENT : GNUTLS_SERVER);
    if (ret != 0) {
	log_debug2(ZONE, LOGT_IO, "Error initializing session for fd #%i: %s", m->fd, gnutls_strerror(ret));
	return 1;
    }
    log_debug2(ZONE, LOGT_EXECFLOW, "Created new session %X", session);

    /* setting algorithm priorities */
    ret = gnutls_set_default_priority(session);
    if (ret != 0) {
	log_debug2(ZONE, LOGT_IO, "Error setting default priorities for fd #%i: %s", m->fd, gnutls_strerror(ret));
    }

    // overwrite protocol priorities?
    if (mio_tls_protocols.find(identity) != mio_tls_protocols.end()) {
	ret = gnutls_protocol_set_priority(session, mio_tls_protocols[identity]);
	if (ret < 0) {
	    log_notice(identity, "error setting protocol priority: %s", gnutls_strerror(ret));
	}
    } else if (mio_tls_protocols.find("*") != mio_tls_protocols.end()) {
	ret = gnutls_protocol_set_priority(session, mio_tls_protocols["*"]);
	if (ret < 0) {
	    log_notice(identity, "error setting protocol priority: %s", gnutls_strerror(ret));
	}
    }

    // overwrite kx algorithm priorities?
    if (mio_tls_kx.find(identity) != mio_tls_kx.end()) {
	ret = gnutls_kx_set_priority(session, mio_tls_kx[identity]);
	if (ret < 0) {
	    log_notice(identity, "error setting kx algorithm priority: %s", gnutls_strerror(ret));
	}
    } else if (mio_tls_kx.find("*") != mio_tls_kx.end()) {
	ret = gnutls_kx_set_priority(session, mio_tls_kx["*"]);
	if (ret < 0) {
	    log_notice(identity, "error setting kx algorithm priority: %s", gnutls_strerror(ret));
	}
    }

    // overwrite cipher priorities?
    if (mio_tls_ciphers.find(identity) != mio_tls_ciphers.end()) {
	ret = gnutls_cipher_set_priority(session, mio_tls_ciphers[identity]);
	if (ret < 0) {
	    log_notice(identity, "error setting cipher algorithm priority: %s", gnutls_strerror(ret));
	}
    } else if (mio_tls_ciphers.find("*") != mio_tls_ciphers.end()) {
	ret = gnutls_cipher_set_priority(session, mio_tls_ciphers["*"]);
	if (ret < 0) {
	    log_notice(identity, "error setting cipher algorithm priority: %s", gnutls_strerror(ret));
	}
    }

    // overwrite certificate priorities?
    if (mio_tls_certtypes.find(identity) != mio_tls_certtypes.end()) {
	ret = gnutls_certificate_type_set_priority(session, mio_tls_certtypes[identity]);
	if (ret < 0) {
	    log_notice(identity, "error setting certificate priorities: %s", gnutls_strerror(ret));
	}
    } else if (mio_tls_certtypes.find("*") != mio_tls_certtypes.end()) {
	ret = gnutls_certificate_type_set_priority(session, mio_tls_certtypes["*"]);
	if (ret < 0) {
	    log_notice(identity, "error setting certificate priorities: %s", gnutls_strerror(ret));
	}
    }

    // overwrite mac algorithm priorities?
    if (mio_tls_mac.find(identity) != mio_tls_mac.end()) {
	ret = gnutls_mac_set_priority(session, mio_tls_mac[identity]);
	if (ret < 0) {
	    log_notice(identity, "error setting mac algorithm priorities: %s", gnutls_strerror(ret));
	}
    } else if (mio_tls_mac.find("*") != mio_tls_mac.end()) {
	ret = gnutls_mac_set_priority(session, mio_tls_mac["*"]);
	if (ret < 0) {
	    log_notice(identity, "error setting mac algorithm priorities: %s", gnutls_strerror(ret));
	}
    }

    // overwrite compression algorithm priorities?
    if (mio_tls_compression.find(identity) != mio_tls_compression.end()) {
	ret = gnutls_compression_set_priority(session, mio_tls_compression[identity]);
	if (ret < 0) {
	    log_notice(identity, "error setting compression algorithm priorities: %s", gnutls_strerror(ret));
	}
    } else if (mio_tls_compression.find("*") != mio_tls_compression.end()) {
	ret = gnutls_compression_set_priority(session, mio_tls_compression["*"]);
	if (ret < 0) {
	    log_notice(identity, "error setting compression algorithm priorities: %s", gnutls_strerror(ret));
	}
    }

    /* setting certificate credentials */
    ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, used_credentials);
    if (ret != 0) {
	log_debug2(ZONE, LOGT_IO, "Error setting certificate credentials for fd #%i: %s", m->fd, gnutls_strerror(ret));
    }
    if (!originator) {
	gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);
    }
    gnutls_dh_set_prime_bits(session, 1024);

    /* associate with the socket */
    gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) m->fd);

    /* use new read/write handlers */
    m->mh->read = MIO_SSL_READ;
    m->mh->write = MIO_SSL_WRITE;

    // close the TLS layer on connection shutdown
    m->mh->close = mio_tls_close;

    /* TLS handshake */
    m->flags.recall_handshake_when_readable = 0;
    m->flags.recall_handshake_when_writeable = 0;
    ret = gnutls_handshake(session);
    if (ret < 0) {
	if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN) {
	    if (gnutls_record_get_direction(session) == 0) {
		m->flags.recall_handshake_when_readable = 1;
		log_debug2(ZONE, LOGT_IO, "TLS layer needs to read data to complete handshake (mio %X, fd #%i)", m, m->fd);
	    } else {
		m->flags.recall_handshake_when_writeable = 1;
		log_debug2(ZONE, LOGT_IO, "TLS layer needs to write data to complete handshake (mio %X, fd #%i)", m, m->fd);
	    }
	    m->mh->handshake = _mio_tls_cont_handshake_server;
	    m->ssl = session;
	    pool_cleanup(m->p, _mio_ssl_cleanup, (void*)session);
	    return 0;
	}

	/* real error happened */
	mio_close(m);
	gnutls_deinit(session);
	log_debug2(ZONE, LOGT_IO, "TLS handshake failed on socket #%i: %s", m->fd, gnutls_strerror(ret));
	return 1;
    }

    m->k.val = 100;
    m->ssl = session;
    log_debug2(ZONE, LOGT_EXECFLOW, "m->ssl is now %X, session=%X", m->ssl, session);

    pool_cleanup(m->p, _mio_ssl_cleanup, (void*)session);

    log_debug2(ZONE, LOGT_IO, "Established TLS layer on socket %d, mio %X", m->fd, m);

    return 0;
}

/**
 * check if two domains are matching
 *
 * Used to check if a domain in a x509 certificate matches an expected domain name
 *
 * @todo take care of punycode encoded domains in the certificate
 *
 * @param p memory pool, that can be used for the comparison
 * @param cert_dom the domain out of a x509 domain, may contain wildcards as in RFC2818
 * @param true_dom the expected domain (may NOT contain wildcards)
 * @return 0 if the domains are matching, non-zero else
 */
static int mio_tls_cert_match(pool p, const char *cert_dom, const char *true_dom) {
    /* sanity check */
    if (p == NULL || cert_dom == NULL || true_dom == NULL) {
	return 1;
    }

    /* does cert_dom contain wildcards? */
    if (strchr(cert_dom, '*') == NULL) {
	/* no wildcards */

	/* make it a JID to get the domains stringpreped */
	jid jid_cert = jid_new(p, cert_dom);
	jid jid_true = jid_new(p, true_dom);

	/* compare */
	return jid_cmp(jid_cert, jid_true);
    } else {
	/* there are wildcards, match domain name fragment by fragment */

	/* only accepting domains, that start with *. in the cert */
	if (j_strncmp(cert_dom, "*.", 2) != 0) {
	    return 1;
	}

	/* to match the matching part has to be bigger than the domain we are expecting */
	size_t match_len = strlen(cert_dom+1);
	size_t true_dom_len = strlen(true_dom);

	/* it can't be a match */
	if (match_len >= true_dom_len) {
	    return 1;
	}

	/* check for match */
	return strcasecmp(true_dom + true_dom_len - match_len, cert_dom+1);
    }
}

/**
 * verify a OpenPGP certificate
 *
 * @param m the mio structure the certificate is verified for
 * @param id_on_xmppAddr the xmpp address the peer claims to be, and that should be checked
 * @param log_id which ID to use for logging if we have to log a message
 * @return 0 if the verification failed, 1 if it succeeded
 */
static int mio_tls_check_openpgp(mio m, char const* id_on_xmppAddr, const std::string& log_id) {
    int ret = 0;
    const gnutls_datum_t *cert_list = NULL;
    unsigned int cert_list_size = 0;

#ifdef HAVE_GNUTLS_EXTRA
    // get the certificate (it's only a single one for OpenPGP)
    cert_list = gnutls_certificate_get_peers(static_cast<gnutls_session_t>(m->ssl), &cert_list_size);
    if (cert_list == NULL || cert_list_size <= 0) {
	log_notice(log_id.c_str(), "Problem verifying certificate: No certificate was found!");
	return 0;
    }

    // parse the key received in the certificate
    gnutls_openpgp_key_t pgpkey = NULL;
    ret = gnutls_openpgp_key_init(&pgpkey);
    if (ret < 0) {
	log_error(log_id.c_str(), "Could not initialize OpenPGP key structure: %s", gnutls_strerror(ret));
	return 0;
    }

    // check if we find the correct entry
    if (id_on_xmppAddr != NULL && strchr(id_on_xmppAddr, '@') == NULL && gnutls_openpgp_key_check_hostname(pgpkey, id_on_xmppAddr)) {
	gnutls_openpgp_key_deinit(pgpkey);
	return 1;
    }

    pool jidpool = pool_new();
    jid expected_jid = jid_new(jidpool, id_on_xmppAddr);

    // else check if there are "xmpp:" prefixed JIDs
    for (int i=0; true; i++) {
	char name[1024*3+5] = "";
	size_t name_len = sizeof(name);

	// get a name from the key
	ret = gnutls_openpgp_key_get_name(pgpkey, i, name, &name_len);

	// check for end of the loop
	if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
	    break;
	}

	// check for error
	if (ret < 0) {
	    log_error(log_id.c_str(), "Could not read name from OpenPGP key structure: %s", gnutls_strerror(ret));
	    gnutls_openpgp_key_deinit(pgpkey);
	    pool_free(jidpool);
	    return 0;
	}

	// it can't be a valid protocol prefixed JID
	if (name_len < 6)
	    continue;

	// correct protocol?
	if (j_strncasecmp(name, "xmpp:", 5) != 0) {
	    // no match of the protocol
	    continue;
	}

	jid this_jid = jid_new(jidpool, name+5);
	if (jid_cmp(expected_jid, this_jid) == 0) {
	    log_debug2(ZONE, LOGT_AUTH, "matched %s on %s", id_on_xmppAddr, name);
	    gnutls_openpgp_key_deinit(pgpkey);
	    pool_free(jidpool);
	    return 1;
	}
    }

    // free memory
    gnutls_openpgp_key_deinit(pgpkey);
    pool_free(jidpool);
#endif
    return 0;
}

/**
 * verify an X.509 certificate chain
 *
 * @param m the mio structure the certificate is verified for
 * @param id_on_xmppAddr the xmpp address the peer claims to be, and that should be checked
 * @param log_id which ID to use for logging if we have to log a message
 * @return 0 if the verification failed, 1 if it succeeded
 */
static int mio_tls_check_x509(mio m, char const* id_on_xmppAddr, const std::string& log_id) {
    int ret = 0;
    int verification_result = 1;
    const gnutls_datum_t *cert_list = NULL;
    unsigned int cert_list_size = 0;

    /* get the certificates */
    cert_list = gnutls_certificate_get_peers(static_cast<gnutls_session_t>(m->ssl), &cert_list_size);
    if (cert_list == NULL || cert_list_size <= 0) {
	log_notice(log_id.c_str(), "Problem verifying certificate: No certificate was found!");
	return 0;
    }

    log_debug2(ZONE, LOGT_AUTH, "We have to verify %i certificates for %s", cert_list_size, id_on_xmppAddr);

    /* iterate on the certificates */
    for (int crt_index = 0; crt_index < cert_list_size; crt_index++) {
	gnutls_x509_crt_t cert = NULL;
	std::string cert_subject;

	/* initialize X.509 certificate structure */
	ret = gnutls_x509_crt_init(&cert);
	if (ret < 0) {
	    log_warn(log_id.c_str(), "Problem initializing the certificate var. Therefore I cannot verify the certificate.");
	    return 0;
	}

	/* XXX begin debugging only
	 *
	std::ostringstream tmpfilename;
	tmpfilename << "/tmp/";
	if (id_on_xmppAddr != NULL) {
	    tmpfilename << id_on_xmppAddr;
	}
	tmpfilename << "_" << crt_index << ".der";

	std::ofstream tmpfile(tmpfilename.str().c_str());

	for (int c=0; c<cert_list[crt_index].size; c++) {
	    tmpfile.put(cert_list[crt_index].data[c]);	// write is not working because of libpth's definitions
	}

	tmpfile.close();
	 *
	 * XXX end debugging only */

	/* get this certificate */
	ret = gnutls_x509_crt_import(cert, &cert_list[crt_index], GNUTLS_X509_FMT_DER);
	if (ret < 0) {
	    log_warn(log_id.c_str(), "Error in loading certificate %i: %s", crt_index, gnutls_strerror(ret));
	    verification_result = 0;
	    gnutls_x509_crt_deinit(cert);
	    cert = NULL;
	    break;
	}

	/* get the DN of the certificate */
	char name[1024];
	size_t name_len = sizeof(name);
	ret = gnutls_x509_crt_get_dn(cert, name, &name_len);
	if (ret < 0) {
	    log_warn(log_id.c_str(), "Error accessing DN of certificate %i: %s", crt_index, gnutls_strerror(ret));
	} else {
	    cert_subject = name;
	}
	log_debug2(ZONE, LOGT_AUTH, "verifying certificate: %s", cert_subject.c_str());

	/* for the first certificate we have to check the subjectAltNames */
	if (crt_index == 0 && id_on_xmppAddr != NULL) {
	    int ext_count = 0;
	    int found_matching_subjectAltName = 0;
	    int found_any_subjectAltName = 0;
	    int may_match_dNSName = 1;

	    log_debug2(ZONE, LOGT_AUTH, "verifying first certificate in chain ...");

	    /* only pure domains may be matched against dNSName */
	    if (id_on_xmppAddr == NULL || strchr(id_on_xmppAddr, '@') != NULL || strchr(id_on_xmppAddr, '/') != NULL) {
		may_match_dNSName = 0;
	    }

	    /* verify id-on-xmppAddr and dNSName */
	    do {
		unsigned char subjectAltName[2048];
		size_t subjectAltName_size = sizeof(subjectAltName);
		unsigned int is_critical = 0;

		ret = gnutls_x509_crt_get_extension_by_oid(cert, "2.5.29.17", ext_count, subjectAltName, &subjectAltName_size, &is_critical);
		if (ret < 0) {
		    if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			log_debug2(ZONE, LOGT_AUTH, "no more subjectAltName extensions (%i)", ext_count);
		    } else {
			log_warn(log_id.c_str(), "error requesting %i-th subjectAltName: %s (%s)", ext_count, gnutls_strerror(ret), cert_subject.c_str());
		    }
		} else {
		    ASN1_TYPE subjectAltName_element = ASN1_TYPE_EMPTY;
		    int cnt = 0;

		    log_debug2(ZONE, LOGT_AUTH, "got a%s subjectAltName extension", is_critical ? " critical" : "");

		    /* we got a subjectAltName */
		    found_any_subjectAltName = 1;

		    /* init subjectAltName_element */
		    ret = asn1_create_element(mio_tls_asn1_tree, "PKIX1.SubjectAltName", &subjectAltName_element);
		    if (ret != ASN1_SUCCESS) {
			log_warn(log_id.c_str(), "error creating asn1 element for PKIX1.SubjectAltName: %s (%s)", libtasn1_strerror(ret), cert_subject.c_str());
			break;
		    }

		    /* decode the extension */
		    ret = asn1_der_decoding(&subjectAltName_element, subjectAltName, subjectAltName_size, NULL);
		    if (ret != ASN1_SUCCESS) {
			log_warn(log_id.c_str(), "error DER decoding subjectAltName extension: %s (%s)", libtasn1_strerror(ret), cert_subject.c_str());
			asn1_delete_structure(&subjectAltName_element);
			break;
		    }

		    /* subjectAltName is a sequence we have to iterate ... */
		    for (cnt = 1; cnt < 1024 && !found_matching_subjectAltName; cnt++) {
			char cnt_string[6];
			char address_type[32];
			int address_type_len = sizeof(address_type);

			snprintf(cnt_string, sizeof(cnt_string), "?%i", cnt);

			log_debug2(ZONE, LOGT_AUTH, "accessing subjectAltName element %s", cnt_string);

			ret = asn1_read_value(subjectAltName_element, cnt_string, address_type, &address_type_len);
			if (ret == ASN1_ELEMENT_NOT_FOUND) {
			    log_debug2(ZONE, LOGT_AUTH, "no more values in subjectAltName (%s)", cnt_string);
			    break;
			}
			if (ret != ASN1_SUCCESS) {
			    log_notice(log_id.c_str(), "error accessing type for %s in subjectAltName: %s (%s)", cnt_string, libtasn1_strerror(ret), cert_subject.c_str());
			    break;
			}

			log_debug2(ZONE, LOGT_AUTH, "... it is of type %s", address_type);

			/* is it a dNSName? */
			if (j_strncmp(address_type, "dNSName", 8) == 0) {
			    if (!may_match_dNSName) {
				log_debug2(ZONE, LOGT_AUTH, "not checking dNSName, as we are not searching for a domain");
			    } else {
				char access_string[14];
				char dNSName[2048];
				int dNSName_len = sizeof(dNSName);
				pool compare_pool = NULL;

				snprintf(access_string, sizeof(access_string), "%s.dNSName", cnt_string);

				ret = asn1_read_value(subjectAltName_element, access_string, dNSName, &dNSName_len);
				if (ret != ASN1_SUCCESS) {
				    log_notice(log_id.c_str(), "error accessing %s in subjectAltName: %s (%s)", access_string, libtasn1_strerror(ret), cert_subject.c_str());
				    break;
				}

				if (dNSName_len >= sizeof(dNSName)) {
				    log_notice(log_id.c_str(), "got a dNSName which is longer then %i B. Skipping ... (%s)", sizeof(dNSName), cert_subject.c_str());
				    break;
				}

				/* zero terminating the dNSName */
				dNSName[dNSName_len] = 0;
				log_debug2(ZONE, LOGT_AUTH, "found dNSName: %s", dNSName);

				/* get a memory pool for doing comparisons */
				compare_pool = pool_new();

				/* compare the dNSName */
				if (mio_tls_cert_match(compare_pool, dNSName, id_on_xmppAddr) == 0) {
				    found_matching_subjectAltName = 1;
				    log_debug2(ZONE, LOGT_AUTH, "match on dNSName: %s", dNSName);
				}

				/* free memory pool */
				pool_free(compare_pool);
				compare_pool = NULL;
			    }
			} else if (j_strncmp(address_type, "otherName", 10) == 0) {
			    char access_string_type[24];
			    char access_string_value[22];
			    char otherNameType[1024];
			    int otherNameType_len = sizeof(otherNameType);
			    unsigned char otherNameValue[1024];
			    int otherNameValue_len = sizeof(otherNameValue);

			    snprintf(access_string_type, sizeof(access_string_type), "%s.otherName.type-id", cnt_string);
			    snprintf(access_string_value, sizeof(access_string_value), "%s.otherName.value", cnt_string);

			    /* get the OID of the otherName */
			    ret = asn1_read_value(subjectAltName_element, access_string_type, otherNameType, &otherNameType_len);
			    if (ret != ASN1_SUCCESS) {
				log_notice(log_id.c_str(), "error accessing type information %s in subjectAltName: %s (%s)", access_string_type, libtasn1_strerror(ret), cert_subject.c_str());
				break;
			    }

			    /* is it an id-on-xmppAddr */
			    if (j_strncmp(otherNameType, "1.3.6.1.5.5.7.8.5", 18) != 0) {
				log_notice(log_id.c_str(), "ignoring unknown otherName in subjectAltName (%s)", cert_subject.c_str());
				break;
			    }

			    /* get the value of the otherName */
			    ret = asn1_read_value(subjectAltName_element, access_string_value, otherNameValue, &otherNameValue_len);
			    if (ret != ASN1_SUCCESS) {
				log_notice(log_id.c_str(), "error accessing value of othername %s in subjectAltName: %s (%s)", access_string_value, libtasn1_strerror(ret), cert_subject.c_str());
				break;
			    }

			    /* okay we now have an UTF8String ... get the content */
			    {
				ASN1_TYPE directoryString_element = ASN1_TYPE_EMPTY;
				char thisIdOnXMPPaddr[3072];
				int thisIdOnXMPPaddr_len = sizeof(thisIdOnXMPPaddr);
				pool jid_pool = NULL;
				jid cert_jid = NULL;

				ret = asn1_create_element(mio_tls_asn1_tree, "PKIX1.DirectoryString", &directoryString_element);
				if (ret != ASN1_SUCCESS) {
				    log_notice(log_id.c_str(), "error creating DirectoryString element: %s (%s)", libtasn1_strerror(ret), cert_subject.c_str());
				    asn1_delete_structure(&directoryString_element);
				    break;
				}

				ret = asn1_der_decoding(&directoryString_element, otherNameValue, otherNameValue_len, NULL);
				if (ret != ASN1_SUCCESS) {
				    log_notice(log_id.c_str(), "error decoding DirectoryString: %s (%s)", libtasn1_strerror(ret), cert_subject.c_str());
				    asn1_delete_structure(&directoryString_element);
				    break;
				}

				ret = asn1_read_value(directoryString_element, "utf8String", thisIdOnXMPPaddr, &thisIdOnXMPPaddr_len);
				if (ret != ASN1_SUCCESS) {
				    log_notice(log_id.c_str(), "error accessing utf8String of DirectoryString: %s (%s)", libtasn1_strerror(ret), cert_subject.c_str());
				    asn1_delete_structure(&directoryString_element);
				    break;
				}

				if (thisIdOnXMPPaddr_len >= sizeof(thisIdOnXMPPaddr)) {
				    log_notice(log_id.c_str(), "id-on-xmppAddr is %i B long ... ignoring (%s)", thisIdOnXMPPaddr_len, cert_subject.c_str());
				    asn1_delete_structure(&directoryString_element);
				    break;
				}

				/* zero-terminate the string */
				thisIdOnXMPPaddr[thisIdOnXMPPaddr_len] = 0;

				/* nameprep the domain */
				jid_pool = pool_new();
				cert_jid = jid_new(jid_pool, thisIdOnXMPPaddr);

				if (cert_jid == NULL || cert_jid->server == NULL) {
				    cert_jid = NULL;
				    pool_free(jid_pool);
				    jid_pool = NULL;

				    log_notice(log_id.c_str(), "invalid id-on-xmppAddr: %s ... skipping this one (%s)", thisIdOnXMPPaddr, cert_subject.c_str());
				    break;
				}

				log_debug2(ZONE, LOGT_AUTH, "found id-on-xmppAddr: %s", jid_full(cert_jid));

				/* compare */
				if (j_strcmp(id_on_xmppAddr, jid_full(cert_jid)) == 0) {
				    found_matching_subjectAltName = 1;
				    log_debug2(ZONE, LOGT_AUTH, "match on id-on-xmppAddr: %s", thisIdOnXMPPaddr);
				}

				/* free memory needed for nameprepping */
				cert_jid = NULL;
				pool_free(jid_pool);
				jid_pool = NULL;

				/* free memory needed to DER decode utf8String */
				asn1_delete_structure(&directoryString_element);
			    }

			} else {
			    log_notice(log_id.c_str(), "ignoring %s in subjectAltName (%s)", address_type, cert_subject.c_str());
			}
		    }

		    asn1_delete_structure(&subjectAltName_element);
		}

		ext_count++;
	    } while (ret >= 0 && !found_matching_subjectAltName);

	    if (found_any_subjectAltName) {
		if (!found_matching_subjectAltName) {
		    log_notice(log_id.c_str(), "Found subjectAltName, but non matched (%s)", cert_subject.c_str());
		    verification_result = 0;
		    gnutls_x509_crt_deinit(cert);
		    cert = NULL;
		    break;
		}
	    } else {
		/* verify subject */
		if (!gnutls_x509_crt_check_hostname(cert, id_on_xmppAddr)) {
		    log_notice(log_id.c_str(), "Certificate subject does not match. (%s)", cert_subject.c_str());
		    verification_result = 0;
		    gnutls_x509_crt_deinit(cert);
		    cert = NULL;
		    break;
		}
	    }
	}

	/* check expiration */
	if (gnutls_x509_crt_get_expiration_time(cert) < time(NULL)) {
	    log_notice(log_id.c_str(), "Certificate %i has expired (%s)", crt_index, cert_subject.c_str());
	    verification_result = 0;
	    gnutls_x509_crt_deinit(cert);
	    cert = NULL;
	    break;
	}
	if (gnutls_x509_crt_get_activation_time(cert) > time(NULL)) {
	    log_notice(log_id.c_str(), "Certificate %i not yet active (%s)", crt_index, cert_subject.c_str());
	    verification_result = 0;
	    gnutls_x509_crt_deinit(cert);
	    cert = NULL;
	    break;
	}
	gnutls_x509_crt_deinit(cert);
    }
    
    return verification_result;
}



/**
 * verify the SSL/TLS certificate of the peer for the given MIO connection
 *
 * @param m the connection for which the peer should be verified
 * @param id_on_xmppAddr the JabberID, that the certificate should be checked for, if NULL it is only checked if the certificate is valid and trusted
 * @return 0 the certificate is invalid, 1 the certificate is valid
 */
int mio_ssl_verify(mio m, const char *id_on_xmppAddr) {
    int ret = 0;
    unsigned int status = 0;
    const gnutls_datum_t *cert_list = NULL;
    unsigned int cert_list_size = 0;
    int crt_index = 0;
    std::string log_id;

    /* sanity checks */
    if (m==NULL || m->ssl==NULL) {
	return 0;
    }

    /* generate id for logging */
    if (id_on_xmppAddr == NULL) {
	log_id = "<unknown peer>";
    } else {
	log_id = id_on_xmppAddr;
    }

    /* check if the certificate is valid */
    ret = gnutls_certificate_verify_peers2(static_cast<gnutls_session_t>(m->ssl), &status);
    if (ret != 0) {
	log_notice(log_id.c_str(), "TLS cert verification failed: %s", gnutls_strerror(ret));
	return 0;
    }
    if (status != 0) {
	std::ostringstream messages;
	bool got_a_message = false;

	if (status&GNUTLS_CERT_INVALID) {
	    got_a_message = true;
	    messages << "not trusted";
	}
	if (status&GNUTLS_CERT_REVOKED) {
	    if (got_a_message)
		messages << ", ";
	    got_a_message = true;
	    messages << "revoked";
	}
	if (status&GNUTLS_CERT_SIGNER_NOT_FOUND) {
	    if (got_a_message)
		messages << ", ";
	    got_a_message = true;
	    messages << "no known issuer";
	}
	if (status&GNUTLS_CERT_SIGNER_NOT_CA) {
	    if (got_a_message)
		messages << ", ";
	    got_a_message = true;
	    messages << "signer is no CA";
	}
	if (status&GNUTLS_CERT_INSECURE_ALGORITHM) {
	    if (got_a_message)
		messages << ", ";
	    got_a_message = true;
	    messages << "insecure algorithm";
	}

	std::string cert_subject;
	if (gnutls_certificate_type_get(static_cast<gnutls_session_t>(m->ssl)) == GNUTLS_CRT_X509) {
	    cert_list = gnutls_certificate_get_peers(static_cast<gnutls_session_t>(m->ssl), &cert_list_size);
	    if (cert_list != NULL && cert_list_size > 0) {
		gnutls_x509_crt_t cert = NULL;
		ret = gnutls_x509_crt_init(&cert);
		if (ret >= 0) {
		    ret = gnutls_x509_crt_import(cert, &cert_list[crt_index], GNUTLS_X509_FMT_DER);
		    if (ret >= 0) {
			char name[1024];
			size_t name_len = sizeof(name);
			ret = gnutls_x509_crt_get_dn(cert, name, &name_len);
			if (ret >= 0 && name_len > 0) {
			    cert_subject = name;
			} else {
			    cert_subject = gnutls_strerror(ret);
			}
		    } else {
			cert_subject = gnutls_strerror(ret);
		    }
		} else {
		    cert_subject = gnutls_strerror(ret);
		}
		gnutls_x509_crt_deinit(cert);
	    } else {
		cert_subject = "<no cert list>";
	    }
	} else {
	    cert_subject = "<no X.509 cert>";
	}

	log_notice(log_id.c_str(), "Certificate verification failed: %s (%s)", got_a_message ? messages.str().c_str() : "unknown reason", cert_subject.c_str());
	return 0;
    }

    /* check if it is a X.509 certificate */
    gnutls_certificate_type_t cert_type = gnutls_certificate_type_get(static_cast<gnutls_session_t>(m->ssl));
    switch (cert_type) {
	case GNUTLS_CRT_X509:
	    return mio_tls_check_x509(m, id_on_xmppAddr, log_id);
	case GNUTLS_CRT_OPENPGP:
	    return mio_tls_check_openpgp(m, id_on_xmppAddr, log_id);
	default:
	    /* no ... we cannot handle other certificates here yet ... declare as invalid */
	    log_notice(log_id.c_str(), "Rejecting certificate as it is no supported certificate format: %s", gnutls_certificate_type_get_name(cert_type));
	    return 0;
    }
}

/**
 * get some information on what protocols are used inside the TLS layer
 *
 * @param m the mio object to request the information for
 * @param buffer where to write the result
 * @param len size of the buffer to place the information in
 */
void mio_tls_get_characteristics(mio m, char* buffer, size_t len) {
    /* sanity checks */
    if (len <= 0) {
	return;
    }
    if (m == NULL || m->ssl == NULL) {
	snprintf(buffer, len, "no TLS");
	return;
    }

    gnutls_session_t session = static_cast<gnutls_session_t>(m->ssl);

    std::ostringstream characteristics;
    characteristics << gnutls_protocol_get_name(gnutls_protocol_get_version(session));
    characteristics << "/";
    characteristics << gnutls_cipher_suite_get_name(gnutls_kx_get(session), gnutls_cipher_get(session), gnutls_mac_get(session));

    snprintf(buffer, len, "%s", characteristics.str().c_str());
}

void mio_tls_get_certtype(mio m, char* buffer, size_t len) {
    /* sanity checks */
    if (len <= 0) {
	return;
    }
    if (m == NULL || m->ssl == NULL) {
	snprintf(buffer, len, "no TLS");
	return;
    }

    snprintf(buffer, len, "%s", gnutls_certificate_type_get_name(gnutls_certificate_type_get(static_cast<gnutls_session_t>(m->ssl))));
}

void mio_tls_get_compression(mio m, char* buffer, size_t len) {
    /* sanity checks */
    if (len <= 0) {
	return;
    }
    if (m == NULL || m->ssl == NULL) {
	snprintf(buffer, len, "no TLS");
	return;
    }

    snprintf(buffer, len, "%s", gnutls_compression_get_name(gnutls_compression_get(static_cast<gnutls_session_t>(m->ssl))));
}
