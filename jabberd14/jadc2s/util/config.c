#include "util.h"
#include "xmlparse/xmlparse.h"

/* if we're building keys longer than this, something is wrong */
#define MAX_KEY_LENGTH (1024)

struct config_data
{
    xht h;
    char key[MAX_KEY_LENGTH];
    int first;
};

typedef struct rkey_st
{
    int flag;
    char *def;
    char *hint;
} *rkey_t;

static void _config_startElement(void *data, const char *name, const char **attrs)
{
    struct config_data *d = (struct config_data *) data;
    char *end;

    /* first one */
    if(d->key[0] == '\0')
        if(!d->first)
            d->first = 1;
        else
            strcpy(d->key, name);

    /* otherwise, append it */
    else
    {
        end = strchr(d->key, '\0');
        *end = '.';
        end++;
        strcpy(end, name);
    }
}

static void _config_endElement(void *data, const char *name)
{
    struct config_data *d = (struct config_data *) data;
    char *end;

    if(*d->key == '\0' && d->first)
        d->first = 0;

    /* backtrack and chop off the rightmost bit */
    for(end = strchr(d->key, '\0'); end != d->key && *end != '.'; end--);

    *end = '\0';
}

static void _config_charData(void *data, const char *s, int len)
{
    struct config_data *d = (struct config_data *) data;
    char *val;

    val = malloc(sizeof(char) * (len + 1));
    memset(val, 0, len + 1);
    strncpy(val, s, len);

    /* !!! should move this to endElement, charData may get called multiple times for one element */
    if(*d->key != '\0' && xhash_get(d->h, d->key) == NULL)
        xhash_put(d->h, pstrdup(xhash_pool(d->h), d->key), pstrdup(xhash_pool(d->h), val));

    free(val);
}

int config_load(xht h, char *file)
{
    struct config_data d;
    FILE *f;
    XML_Parser p;
    int done, len;
    char buf[1024];

    d.h = h;
    memset(d.key, 0, MAX_KEY_LENGTH);
    d.first = 0;

    f = fopen(file, "r");
    if(f == NULL)
    {
        fprintf(stderr, "config_load: couldn't open %s for reading: %s\n", file, strerror(errno));
        return 1;
    }

    p = XML_ParserCreate(NULL);
    if(p == NULL)
    {
        fprintf(stderr, "config_load: couldn't allocate XML parser\n");
        fclose(f);
        return 1;
    }

    XML_SetUserData(p, (void *) &d);
    XML_SetElementHandler(p, _config_startElement, _config_endElement);
    XML_SetCharacterDataHandler(p, _config_charData);

    for(;;)
    {
        len = fread(buf, 1, 1024, f);
        if(ferror(f))
        {
            fprintf(stderr, "config_load: read error: %s\n", strerror(errno));
            XML_ParserFree(p);
            fclose(f);
            return 1;
        }
        done = feof(f);

        if(!XML_Parse(p, buf, len, done))
        {
            fprintf(stderr, "config_load: parse error at line %d: %s\n", XML_GetCurrentLineNumber(p), XML_ErrorString(XML_GetErrorCode(p)));
            XML_ParserFree(p);
            fclose(f);
            return 1;
        }

        if(done)
            break;
    }

    XML_ParserFree(p);
    fclose(f);

    return 0;
}

int config_cmdline(xht h, char *pair) {
    char *key, *val;

    key = pair;
    val = strchr(pair, '=');
    if(val != NULL)
    {
        *val = '\0';
        val++;
    }
    
    if(key == NULL || val == NULL || *key == '\0' || *val =='\0')
    {
        fprintf(stderr, "config_cmdline: malformed option, ignoring\n");
        return 1;
    }

    xhash_put(h, pstrdup(xhash_pool(h), key), pstrdup(xhash_pool(h), val));

    return 0;
}

char *config_validate(xht cfg, xht reg)
{
    /* !!! spin through reg, checking against cfg to make sure require flags are set */
    /* !!! return string describing which required ones aren't set? */
    return NULL;
}

void config_reg(xht reg, char *key, int flag, char *def, char *hint)
{
    rkey_t rkey;

    if(reg == NULL || key == NULL) return;

    rkey = pmalloco(xhash_pool(reg),sizeof(struct rkey_st));
    rkey->flag = flag;
    if(def != NULL)
        rkey->def = pstrdup(xhash_pool(reg),def);
    if(hint != NULL)
        rkey->hint = pstrdup(xhash_pool(reg),hint);

    xhash_put(reg, pstrdup(xhash_pool(reg), key), (void*)rkey);
}

char *config_template(xht reg)
{
    /* !!! generate a nice config template, like:
    <foo>

        <bar>
        
            <!-- this is a required field -->
            <test>foobar</test>

            <!-- this is an optional field
            <foobar>test</foobar>
            -->

            <!-- this is a required field with no default -->
            <field></field>

        </bar>

    </foo>
    */

    /* !!! other template outputs, like foo.bar.test=foobar? */
    return NULL;
}
