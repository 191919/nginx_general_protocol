
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_GP_H_INCLUDED_
#define _NGX_GP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>

#if (NGX_GP_SSL)
#include "ngx_gp_ssl_module.h"
#endif



typedef struct {
    void                  **main_conf;
    void                  **srv_conf;
} ngx_gp_conf_ctx_t;


typedef struct {
    u_char                  sockaddr[NGX_SOCKADDRLEN];
    socklen_t               socklen;

    /* server ctx */
    ngx_gp_conf_ctx_t    *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_GP_SSL)
    unsigned                ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
} ngx_gp_listen_t;


typedef struct {
    ngx_gp_conf_ctx_t    *ctx;
    ngx_str_t               addr_text;
#if (NGX_GP_SSL)
    ngx_uint_t              ssl;    /* unsigned   ssl:1; */
#endif
} ngx_gp_addr_conf_t;

typedef struct {
    in_addr_t               addr;
    ngx_gp_addr_conf_t    conf;
} ngx_gp_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr         addr6;
    ngx_gp_addr_conf_t    conf;
} ngx_gp_in6_addr_t;

#endif


typedef struct {
    /* ngx_gp_in_addr_t or ngx_gp_in6_addr_t */
    void                   *addrs;
    ngx_uint_t              naddrs;
} ngx_gp_port_t;


typedef struct {
    int                     family;
    in_port_t               port;
    ngx_array_t             addrs;       /* array of ngx_gp_conf_addr_t */
} ngx_gp_conf_port_t;


typedef struct {
    struct sockaddr        *sockaddr;
    socklen_t               socklen;

    ngx_gp_conf_ctx_t    *ctx;

    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_GP_SSL)
    unsigned                ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
} ngx_gp_conf_addr_t;


typedef struct {
    ngx_array_t             servers;     /* ngx_gp_core_srv_conf_t */
    ngx_array_t             listen;      /* ngx_gp_listen_t */
} ngx_gp_core_main_conf_t;


typedef struct ngx_gp_protocol_s  ngx_gp_protocol_t;


typedef struct {
    ngx_gp_protocol_t    *protocol;

    ngx_msec_t              timeout;
    ngx_msec_t              resolver_timeout;

    ngx_flag_t              so_keepalive;

    ngx_str_t               server_name;

    u_char                 *file_name;
    ngx_int_t               line;

    /* server ctx */
    ngx_gp_conf_ctx_t    *ctx;
} ngx_gp_core_srv_conf_t;


typedef enum {
    ngx_flash_policy_start = 0,
    ngx_flash_policy_user,
    ngx_flash_policy_passwd,
    ngx_flash_policy_auth_login_username,
    ngx_flash_policy_auth_login_password,
    ngx_flash_policy_auth_plain,
    ngx_flash_policy_auth_cram_md5
} ngx_flash_policy_state_e;

typedef struct {
    uint32_t                signature;         /* "GPGP" */

    ngx_connection_t       *connection;

    ngx_str_t               out;
    ngx_buf_t              *buffer;

    void                  **ctx;
    void                  **main_conf;
    void                  **srv_conf;

    ngx_uint_t              gp_state;

    unsigned                protocol:3;
    unsigned                blocked:1;
    unsigned                quit:1;

    ngx_uint_t              command;

    /* used to parse POP3/IMAP/SMTP command */

    ngx_uint_t              state;
} ngx_gp_session_t;


typedef struct {
    ngx_str_t              *client;
    ngx_gp_session_t     *session;
} ngx_gp_log_ctx_t;


#define NGX_FLASH_POLICY_REQUEST         1
#define NGX_GP_PARSE_INVALID_COMMAND  9999


typedef void (*ngx_gp_init_session_pt)(ngx_gp_session_t *s,
    ngx_connection_t *c);
typedef void (*ngx_gp_init_protocol_pt)(ngx_event_t *rev);
typedef void (*ngx_gp_auth_state_pt)(ngx_event_t *rev);
typedef ngx_int_t (*ngx_gp_parse_command_pt)(ngx_gp_session_t *s);


struct ngx_gp_protocol_s {
    ngx_str_t                   name;
    in_port_t                   port[4];
    ngx_uint_t                  type;

    ngx_gp_init_session_pt    init_session;
    ngx_gp_init_protocol_pt   init_protocol;
    ngx_gp_parse_command_pt   parse_command;
    ngx_gp_auth_state_pt      auth_state;

    ngx_str_t                   internal_server_error;
};


typedef struct {
    ngx_gp_protocol_t        *protocol;

    void                       *(*create_main_conf)(ngx_conf_t *cf);
    char                       *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                       *(*create_srv_conf)(ngx_conf_t *cf);
    char                       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                      void *conf);
} ngx_gp_module_t;


#define NGX_GP_MODULE         0x50475047     /* "GPGP" */

#define NGX_GP_MAIN_CONF      0x02000000
#define NGX_GP_SRV_CONF       0x04000000


#define NGX_GP_MAIN_CONF_OFFSET  offsetof(ngx_gp_conf_ctx_t, main_conf)
#define NGX_GP_SRV_CONF_OFFSET   offsetof(ngx_gp_conf_ctx_t, srv_conf)


#define ngx_gp_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define ngx_gp_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define ngx_gp_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;


#define ngx_gp_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_gp_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]

#define ngx_gp_conf_get_module_main_conf(cf, module)                       \
    ((ngx_gp_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_gp_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_gp_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]


#if (NGX_GP_SSL)
void ngx_gp_starttls_handler(ngx_event_t *rev);
ngx_int_t ngx_gp_starttls_only(ngx_gp_session_t *s, ngx_connection_t *c);
#endif


void ngx_gp_init_connection(ngx_connection_t *c);

void ngx_gp_send(ngx_event_t *wev);
ngx_int_t ngx_gp_read_command(ngx_gp_session_t *s, ngx_connection_t *c);
void ngx_gp_auth(ngx_gp_session_t *s, ngx_connection_t *c);
void ngx_gp_close_connection(ngx_connection_t *c);
void ngx_gp_session_internal_server_error(ngx_gp_session_t *s);
u_char *ngx_gp_log_error(ngx_log_t *log, u_char *buf, size_t len);

extern ngx_uint_t    ngx_gp_max_module;
extern ngx_module_t  ngx_gp_core_module;


#endif /* _NGX_GP_H_INCLUDED_ */
