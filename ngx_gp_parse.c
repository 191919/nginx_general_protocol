
/*
 * Copyright (C) jh, 191919@gmail.com
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_gp.h"

/*

Flash Player sends:

"<policy-file-request/>\x00"

We reply:

"<?xml version=\"1.0\"?>"
"<cross-domain-policy>"
"<site-control permitted-cross-domain-policies=\"all\"/>"
"<allow-access-from domain=\"*\" to-ports=\"*\" />"
"</cross-domain-policy>"

*/

static u_char flash_request[] = "<policy-file-request/>";

ngx_int_t
ngx_gp_flash_policy_parse_command(ngx_gp_session_t *s)
{
	u_char      ch, *p, *c;

    for (p = s->buffer->pos; p < s->buffer->last; p++) {
        ch = *p;

		if (ch == '\0') {
			c = s->buffer->start;

            if (p - c == sizeof(flash_request)) {

				if (ngx_memcmp(c, flash_request, sizeof(flash_request)) == 0)
                {
                	s->command = NGX_FLASH_POLICY_REQUEST;
					goto done;
                } else {
                    goto invalid;
                }
            } else {
                goto invalid;
            }
		}
    }

    s->buffer->pos = p;
    s->state = 0;

    return NGX_AGAIN;

done:

    s->buffer->pos = p + 1;
	s->state = 0;

    return NGX_OK;

invalid:

    s->state = 0;

    return NGX_GP_PARSE_INVALID_COMMAND;
}
