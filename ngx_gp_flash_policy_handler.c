
/*
 * Copyright (C) jh, 191919@gmail.com
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_gp.h"
#include "ngx_gp_flash_policy_module.h"


static ngx_int_t ngx_gp_flash_policy_user(ngx_gp_session_t *s, ngx_connection_t *c);

static u_char  pop3_invalid_command[] = "<error type=\"bad request\"/>" CRLF;

static u_char cross_domain_policy[] =
"<?xml version=\"1.0\"?>"
"<cross-domain-policy>"
"<site-control permitted-cross-domain-policies=\"all\"/>"
"<allow-access-from domain=\"*\" to-ports=\"*\" />"
"</cross-domain-policy>";

void
ngx_gp_flash_policy_init_session(ngx_gp_session_t *s, ngx_connection_t *c)
{
    ngx_gp_core_srv_conf_t  *cscf;
    ngx_gp_flash_policy_srv_conf_t  *pscf;

    pscf = ngx_gp_get_module_srv_conf(s, ngx_gp_flash_policy_module);
    cscf = ngx_gp_get_module_srv_conf(s, ngx_gp_core_module);

    c->read->handler = ngx_gp_flash_policy_init_protocol;

    ngx_add_timer(c->read, cscf->timeout);

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_gp_close_connection(c);
    }

    ngx_gp_send(c->write);
}


void
ngx_gp_flash_policy_init_protocol(ngx_event_t *rev)
{
    ngx_connection_t    *c;
    ngx_gp_session_t  *s;

    c = rev->data;

    c->log->action = "in auth state";

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_gp_close_connection(c);
        return;
    }

    s = c->data;

    if (s->buffer == NULL) {
        s->buffer = ngx_create_temp_buf(c->pool, 128);
        if (s->buffer == NULL) {
            ngx_gp_session_internal_server_error(s);
            return;
        }
    }

    s->gp_state = ngx_flash_policy_start;
    c->read->handler = ngx_gp_flash_policy_auth_state;

    ngx_gp_flash_policy_auth_state(rev);
}


void
ngx_gp_flash_policy_auth_state(ngx_event_t *rev)
{
    ngx_int_t            rc;
    ngx_connection_t    *c;
    ngx_gp_session_t  *s;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, c->log, 0, "flash_policy auth state");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_gp_close_connection(c);
        return;
    }

    if (s->out.len) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, c->log, 0, "flash_policy send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = ngx_gp_read_command(s, c);

    if (rc == NGX_AGAIN || rc == NGX_ERROR) {
        return;
    }

    if (rc == NGX_OK) {
        switch (s->gp_state) {

        case ngx_flash_policy_start:

            switch (s->command) {

            case NGX_FLASH_POLICY_REQUEST:
                rc = ngx_gp_flash_policy_user(s, c);
                break;

            default:
                rc = NGX_GP_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        }
    }

    switch (rc) {

    case NGX_DONE:
        ngx_gp_auth(s, c);
        return;

    case NGX_ERROR:
        ngx_gp_session_internal_server_error(s);
        return;

    case NGX_GP_PARSE_INVALID_COMMAND:
        s->gp_state = ngx_flash_policy_start;
        s->state = 0;

        ngx_str_set(&s->out, pop3_invalid_command);

        /* fall through */

    case NGX_OK:

        s->buffer->pos = s->buffer->start;
        s->buffer->last = s->buffer->start;

        ngx_gp_send(c->write);
		s->quit = 1;
    }
}

static ngx_int_t
ngx_gp_flash_policy_user(ngx_gp_session_t *s, ngx_connection_t *c)
{
	ngx_str_set(&s->out, cross_domain_policy);

    s->gp_state = ngx_flash_policy_user;

    return NGX_OK;
}
