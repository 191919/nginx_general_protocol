
/*
 * Copyright (C) jh, 191919@gmail.com
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_gp.h"
#include "ngx_gp_flash_policy_module.h"


static void *ngx_gp_flash_policy_create_srv_conf(ngx_conf_t *cf);
static char *ngx_gp_flash_policy_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *
ngx_gp_flash_policy_allow_access_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_str_t  ngx_gp_flash_policy_default_allow_access_from[] = {
    ngx_string("*:*"),
    ngx_null_string
};

static ngx_gp_protocol_t  ngx_gp_flash_policy_protocol = {
    ngx_string("flash_policy"),
    { 843, 0, 0, 0 },
    0,

    ngx_gp_flash_policy_init_session,
    ngx_gp_flash_policy_init_protocol,
    ngx_gp_flash_policy_parse_command,
    ngx_gp_flash_policy_auth_state,

    ngx_string("<error type=\"internal server error\"/>")
};


static ngx_command_t  ngx_gp_flash_policy_commands[] = {

    { ngx_string("allow_access_from"),
      NGX_GP_MAIN_CONF|NGX_GP_SRV_CONF|NGX_CONF_1MORE,
      ngx_gp_flash_policy_allow_access_from,
      NGX_GP_SRV_CONF_OFFSET,
      offsetof(ngx_gp_flash_policy_srv_conf_t, allow_access_froms),
      NULL },

      ngx_null_command
};


static ngx_gp_module_t  ngx_gp_flash_policy_module_ctx = {
    &ngx_gp_flash_policy_protocol,               /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_gp_flash_policy_create_srv_conf,         /* create server configuration */
    ngx_gp_flash_policy_merge_srv_conf           /* merge server configuration */
};


ngx_module_t  ngx_gp_flash_policy_module = {
    NGX_MODULE_V1,
    &ngx_gp_flash_policy_module_ctx,             /* module context */
    ngx_gp_flash_policy_commands,                /* module directives */
    NGX_GP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

char *
ngx_gp_flash_policy_allow_access_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t    *c, *value;
    ngx_uint_t    i;
    ngx_array_t  *a;

    a = (ngx_array_t *) (p + cmd->offset);

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        c = ngx_array_push(a);
        if (c == NULL) {
            return NGX_CONF_ERROR;
        }

        *c = value[i];
    }

    return NGX_CONF_OK;
}

static void *
ngx_gp_flash_policy_create_srv_conf(ngx_conf_t *cf)
{
    ngx_gp_flash_policy_srv_conf_t  *pscf;

    pscf = ngx_pcalloc(cf->pool, sizeof(ngx_gp_flash_policy_srv_conf_t));
    if (pscf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&pscf->allow_access_froms, cf->pool, 4, sizeof(ngx_str_t))
        != NGX_OK)
    {
        return NULL;
    }

    return pscf;
}

static char *
ngx_gp_flash_policy_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_gp_flash_policy_srv_conf_t *prev = parent;
    ngx_gp_flash_policy_srv_conf_t *conf = child;

    u_char      *p;
    size_t       size;
    ngx_str_t   *c, *d;
    ngx_uint_t   i;

    if (conf->allow_access_froms.nelts == 0) {
        conf->allow_access_froms = prev->allow_access_froms;
    }

    if (conf->allow_access_froms.nelts == 0) {

        for (d = ngx_gp_flash_policy_default_allow_access_from; d->len; d++) {
            c = ngx_array_push(&conf->allow_access_froms);
            if (c == NULL) {
                return NGX_CONF_ERROR;
            }

            *c = *d;
        }
    }

	size = sizeof(
		"<?xml version=\"1.0\"?>" CRLF
		"<cross-domain-policy>" CRLF
		"<site-control permitted-cross-domain-policies=\"all\"/>" CRLF
		"</cross-domain-policy>" CRLF) - 1;

    c = conf->allow_access_froms.elts;
    for (i = 0; i < conf->allow_access_froms.nelts; i++) {
		char* b = ngx_strchr(c[i].data, ':');
		size += sizeof("<allow-access-from domain=\"\" to-ports=\"\" />" CRLF) - 1;
        size += c[i].len;
		if (b == NULL) {
			++size; /* '*' */
		}
    }

    p = ngx_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->policy_content.len = size;
    conf->policy_content.data = p;
	
	p = ngx_cpymem(p,
		"<?xml version=\"1.0\"?>" CRLF
		"<cross-domain-policy>" CRLF
		"<site-control permitted-cross-domain-policies=\"all\"/>" CRLF,
		sizeof(
			"<?xml version=\"1.0\"?>" CRLF
			"<cross-domain-policy>" CRLF
			"<site-control permitted-cross-domain-policies=\"all\"/>" CRLF) - 1);

    for (i = 0; i < conf->allow_access_froms.nelts; i++) {
		u_char buf[256];
		size_t len;
		int f = 0;
		char* b = ngx_strchr(c[i].data, ':');
		if (b == NULL)
		{
			b = "*";
		}
		else
		{
			*b++ = '\0';
			f = 1;
		}
		len = ngx_snprintf(buf, sizeof(buf)-1, "<allow-access-from domain=\"%s\" to-ports=\"%s\" />" CRLF, c[i].data, b) - buf;
        p = ngx_cpymem(p, buf, len);
		if (f) {
			*b = ':';
		}
    }

	p = ngx_cpymem(p, "</cross-domain-policy>" CRLF,
		sizeof("</cross-domain-policy>" CRLF) - 1);

    return NGX_CONF_OK;
}
