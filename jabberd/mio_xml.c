#include <jabberd.h>

/* *******************************************
 * Internal Expat Callbacks
 * *******************************************/

void _mio_xstream_startElement(mio m, const char* name, const char** attribs)
{
    /* If stacknode is NULL, we are starting a new packet and must
       setup for by pre-allocating some memory */
    if (m->stacknode == NULL)
    {
	    pool p = pool_heap(5 * 1024); /* 5k, typically 1-2k each, plus copy of self
				   and workspace */
	    m->stacknode = xmlnode_new_tag_pool(p, name);
	    xmlnode_put_expat_attribs(m->stacknode, attribs);

	    /* If the root is 0, this must be the root node.. */
	    if (m->root == 0)
	    {
            if(m->cb != NULL)
	            (*(mio_xml_cb)m->cb)(m, MIO_XML_ROOT, m->cb_arg, m->stacknode);
	        m->stacknode = NULL;
            m->root = 1; 
	    }
    }
    else 
    {
	    m->stacknode = xmlnode_insert_tag(m->stacknode, name);
	    xmlnode_put_expat_attribs(m->stacknode, attribs);
    }
}

void _mio_xstream_endElement(mio m, const char* name)
{
    /* If the stacknode is already NULL, then this closing element
       must be the closing ROOT tag, so notify and exit */
    if (m->stacknode == NULL)
    {
        if(m->cb != NULL)
	        (*(mio_std_cb)m->cb)(m, MIO_CLOSED, m->cb_arg);
    }
    else
    {
	    xmlnode parent = xmlnode_get_parent(m->stacknode);
	    /* Fire the NODE event if this closing element has no parent */
	    if (parent == NULL)
	    {
            if(m->cb != NULL)
	            (*(mio_xml_cb)m->cb)(m, MIO_XML_NODE, m->cb_arg, m->stacknode);
	    }
	    m->stacknode = parent;
    }
}

void _mio_xstream_CDATA(mio m, const char* cdata, int len)
{
    if (m->stacknode != NULL)
	xmlnode_insert_cdata(m->stacknode, cdata, len);
}

void _mio_xstream_cleanup(void* arg)
{
    mio m = (void*)arg;

    xmlnode_free(m->stacknode);
    XML_ParserFree(m->parser);
    m->parser = NULL;
}

mio _mio_xstream_init(mio m)
{
    log_debug(ZONE, "INIT EXPAT FOR SOCKET %d", m->fd);
    if (m != NULL)
    {
	/* Initialize the parser */
	m->parser = XML_ParserCreate(NULL);
	XML_SetUserData(m->parser, m);
	XML_SetElementHandler(m->parser, (void*)_mio_xstream_startElement, 
			      (void*)_mio_xstream_endElement);
	XML_SetCharacterDataHandler(m->parser, (void*)_mio_xstream_CDATA);
	/* Setup a cleanup routine to release the parser when everything
	   is done */
	pool_cleanup(m->p, _mio_xstream_cleanup, (void*)m);
    }
    return m;
}

/* this function is called on a readable socket */
int _mio_xml_read(mio m)
{
    int  maxlen, 
         len;
    char buff[8192]; /* max socket read */

    log_debug(ZONE, "READING FROM XML_READ");

    maxlen = KARMA_READ_MAX(m->k.val);

    if(maxlen > 8191) maxlen = 8191;

    len = MIO_READ_FUNC(m->fd, buff, maxlen);

    if(len == 0)
        return -1;

    if(len < 0)
    {
    log_debug(ZONE, "ERROR READING FROM XML_READ");
        if(errno == EWOULDBLOCK || errno == EINTR || errno == EAGAIN) 
            return 0;
        else
            return -1;
    }

    if(karma_check(&m->k, len))
    { /* they read the max, tsk tsk */
        if(m->k.val <= 0) /* ran out of karma */
        {
            log_notice("MIO_XML_READ", "socket from %s is out of karma", m->ip);
            return 0;
        }
    }

    buff[len] = '\0';
    
    /* init the parser if this is the first read call */
    if(m->parser == NULL)
        _mio_xstream_init(m);

    if(XML_Parse(m->parser, buff, len, 0) < 0)
    {
    log_debug(ZONE, "ERROR READING FROM XML_READ");
        if(m->cb != NULL)
            (*(mio_std_cb)m->cb)(m, MIO_ERROR, m->cb_arg);
        return -1;
    }
}
