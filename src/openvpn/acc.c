/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2025 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2025 Arne Schwabe <arne@rfc2549.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include <string.h>
#include "buffer.h"
#include "push_utils.h"
#include "error.h"
#include "acc.h"
#include "forward.h"

void
receive_acc_message(struct context *c, const struct buffer *buffer)
{
    struct gc_arena gc = gc_new();
    const char *err_reason = "";

    /* Example message: ACC,muppets,15,A,I am Miss Piggy */
    struct buffer buf = *buffer;

    if (!buf_advance(&buf, strlen("ACC"))  || buf_read_u8(&buf) != ',' || !BLEN(&buf))
    {
        err_reason = "missing , after ACC";
        goto err;
    }

    /* extract protocol, payload length, flags substrings */
    char *protocol = extract_field(&buf, ',', &gc);
    if (!protocol)
    {
        err_reason = "could not extract protocol field";
        goto err;
    }
    int payload_len = 0;
    if (!buffer_read_int(&buf, &payload_len))
    {
        err_reason = "could not extract payload length field";
        goto err;
    }

    /* comma after the length */
    if (buf_read_u8(&buf) != ',')
    {
        err_reason = "missing , after payload len";
        goto err;
    }

    char *flags = extract_field(&buf, ',', &gc);

    if (!flags)
    {
        err_reason = "could not extract flags field";
        goto err;
    }

    /* We have a final NUL byte in the control message buffer */
    if (buf_len(&buf)  != payload_len + 1)
    {
        char *tmp  = gc_malloc(512, 1, &gc);
        snprintf(tmp, 512, "field length %d, payload length %d mismatch",
                 payload_len, buf_len(&buf) - 1);
        err_reason = tmp;
        goto err;
    }

    bool base64enc = false;
    bool asciienc = false;
    bool fragment = false;


    for (const char *flag = flags; *flag != '\0'; flag++)
    {
        if (*flag == 'A')
        {
            asciienc = true;
        }
        else if (*flag == '6')
        {
            base64enc = true;
        }
        else if (*flag == 'F')
        {
            fragment = true;
        }
        else
        {
            err_reason = "Unknown flag in flags";
            goto err;
        }
    }

    /* The message should be encoded with exactly one encoding */
    if (base64enc + asciienc != 1)
    {
        char *tmp  = gc_malloc(512, 1, &gc);
        snprintf(tmp, 512, "number of encodings must be exactly one "
                 "(B64=%d, ASCII=%d)", base64enc, asciienc);
        err_reason = tmp;
        goto err;
    }

#ifdef ENABLE_MANAGEMENT
    const char *payload_msg = NULL;

    /* For simplicity, we always encode payload to be base64 encoded
     * if not already in base64 format */
    if (asciienc)
    {
        char *b64out = NULL;
        ASSERT(openvpn_base64_encode(BPTR(&buf), payload_len, &b64out) >= 0);
        gc_addspecial(b64out, free, &gc);
        payload_msg = b64out;
    }
    else
    {
        payload_msg = BSTR(&buf);
    }

    if (management)
    {
        struct tls_session *session = &c->c2.tls_multi->session[TM_ACTIVE];
        struct man_def_auth_context *mda = session->opt->mda_context;
        unsigned int mda_key_id = get_primary_key(c->c2.tls_multi)->mda_key_id;


        msg(M_CLIENT, ">CLIENT:ACC,%lu,%u,%s,%d,%s",
            mda->cid, mda_key_id, protocol, fragment, payload_msg);
    }
#endif /* ifdef ENABLE_MANAGEMENT */
    msg(D_PUSH, "custom app control message (protocol '%s', fragment %d)",
        protocol, fragment);

    gc_free(&gc);
    return;

err:
    dmsg(D_PUSH, "BUF CONTENT: %s",
         format_hex(BPTR(&buf), BLEN(&buf), 80, &gc));

    msg(D_PUSH_ERRORS, "WARNING: Received malformed custom app control channel "
        "(%s) message control message: %s", err_reason,
        BSTR(buffer));
    gc_free(&gc);
}


bool
send_acc_message(struct tls_multi *tls_multi,
                 struct tls_session *session,
                 const char *protocol, bool fragment,
                 const char *msg, bool base64)
{
    /* TODO check client capabilities */
    /* 3 for the encoding, potential F, and , 1 for the final flag, 5 for the message size itself */
    const size_t max_header_size = strlen("ACC,") + 3 + strlen(protocol) + 1 + 5;

    size_t len = max_header_size + strlen(msg);

    if (len > PUSH_BUNDLE_SIZE)
    {
        return false;
    }

    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(len, &gc);

    /* Example message: ACC,muppets,15,A,I am Miss Piggy */
    buf_printf(&buf, "ACC,%s,%zu,%s%s,%s", protocol,
               strlen(msg),
               base64 ? "6" : "A",
               fragment ? ":F" : "",
               msg);

    send_control_channel_string_dowork(session, BSTR(&buf), D_PUSH);
    return true;
}
