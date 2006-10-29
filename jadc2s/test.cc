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

#include "util/util.h"
#include <iostream>

int main() {
    std::cout << "NOTE: This is currently only testing code. jadc2s (now called\n"
	"xmppd-c2s) is currently rewritten. On production systems revision\n"
	"1287 is the currently recommended version of jadc2s." << std::endl;
    return 0;
}
