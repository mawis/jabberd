/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "License").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the License.  You
 * may obtain a copy of the License at http://www.jabber.com/license/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2000 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * --------------------------------------------------------------------------*/

#include <jabberd.h>

/* *******************************************
 * Internal Expat Callbacks
 * *******************************************/


void _mio_xstream_callback(int type, xmlnode x, void* arg)
{
    mio m = (mio)arg;

    if(type == XSTREAM_ROOT)
        (*(mio_xml_cb)m->cb)(m, MIO_XML_ROOT, m->cb_arg, x);
    else if(type == XSTREAM_NODE)
        (*(mio_xml_cb)m->cb)(m, MIO_XML_NODE, m->cb_arg, x);
    else if(type == XSTREAM_CLOSE)
        mio_close(m);

}


void _mio_xstream_init(mio m)
{
    if (m != NULL)
    {
	    /* Initialize the parser */
        m->parser = xstream_new(m->p, _mio_xstream_callback, m);
    }
}

/* this function is called when a socket reads data */
void _mio_xml_parser(mio m, const void *buf, size_t bufsz)
{
    /* init the parser if this is the first read call */
    if(m->parser == NULL)
        _mio_xstream_init(m);

    if(xstream_eat(m->parser, (char*)buf, bufsz) > XSTREAM_NODE)
        if(m->cb != NULL)
        {
            (*(mio_std_cb)m->cb)(m, MIO_ERROR, m->cb_arg);
            mio_write(m, NULL, "<stream:error>Invalid XML</stream:error>", -1);
            mio_close(m);
        }
}
