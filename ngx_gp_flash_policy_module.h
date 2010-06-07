
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_GP_POP3_MODULE_H_INCLUDED_
#define _NGX_GP_POP3_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_gp.h"


typedef struct {
    ngx_array_t  allow_access_froms;
} ngx_gp_flash_policy_srv_conf_t;


void ngx_gp_flash_policy_init_session(ngx_gp_session_t *s, ngx_connection_t *c);
void ngx_gp_flash_policy_init_protocol(ngx_event_t *rev);
void ngx_gp_flash_policy_auth_state(ngx_event_t *rev);
ngx_int_t ngx_gp_flash_policy_parse_command(ngx_gp_session_t *s);


extern ngx_module_t  ngx_gp_flash_policy_module;


#endif /* _NGX_GP_POP3_MODULE_H_INCLUDED_ */
