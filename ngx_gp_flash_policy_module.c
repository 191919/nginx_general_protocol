
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
      NULL,
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
    return NGX_CONF_OK;
}
