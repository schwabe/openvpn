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
#include "push_util.h"
#include "error.h"
#include "acc.h"
#include "forward.h"

enum acc_message_flag
{
    ACC_MESSAGE_FLAGS_ASCII = 1,
    ACC_MESSAGE_FLAGS_BASE64 = 2,
    ACC_MESSAGE_FLAGS_FRAGMENT = 4,
};


static void
log_acc_message(struct context *c, const struct buffer *buf, int payload_len,
                const char *protocol, int flags)
{
#ifdef ENABLE_MANAGEMENT
    struct gc_arena gc = gc_new();
    const char *payload_msg = NULL;

    /* For simplicity, we always encode payload to be base64 encoded
     * if not already in base64 format */
    if (flags & ACC_MESSAGE_FLAGS_ASCII)
    {
        char *b64out = NULL;
        ASSERT(openvpn_base64_encode(BPTR(buf), payload_len, &b64out) >= 0);
        gc_addspecial(b64out, free, &gc);
        payload_msg = b64out;
    }
    else
    {
        payload_msg = BSTR(buf);
    }
    bool fragment = flags & ACC_MESSAGE_FLAGS_FRAGMENT;

    if (management)
    {
        struct tls_session *session = &c->c2.tls_multi->session[TM_ACTIVE];

        struct man_def_auth_context *mda = session->opt->mda_context;
        if (c->mode == MODE_SERVER)
        {
            /* server mode. Report client context */
            unsigned int mda_key_id = get_primary_key(c->c2.tls_multi)->mda_key_id;
            msg(M_CLIENT, ">CLIENT:ACC,%lu,%u,%s,%d,%s",
                mda->cid, mda_key_id, protocol, fragment, payload_msg);
        }
        else
        {
            /* Client mode. Do not a report a CLIENT id */
            msg(M_CLIENT, ">ACC:%s,%d,%s", protocol, fragment, payload_msg);
        }
    }
    gc_free(&gc);
#endif /* ifdef ENABLE_MANAGEMENT */
    msg(D_PUSH, "custom app control message (protocol '%s', fragment %d)",
        protocol, fragment);
}


/**
 *  Parses the flags field of an app control message and moves the
 *  buffer past the flags string. If there is an
 *  error parsing the flags field the method returns -1 and
 *  puts the error reason in err_reason
 */
static int
parse_acc_message_flags(struct buffer *buf, const char **err_reason, struct gc_arena *gc)
{
    const char *flags = extract_field(buf, ',', gc);

    if (!flags)
    {
        *err_reason = "could not extract flags field";
        return -1;
    }


    int acc_flags = 0;

    for (const char *flag = flags; *flag != '\0'; flag++)
    {
        if (*flag == 'A')
        {
            acc_flags |= ACC_MESSAGE_FLAGS_ASCII;
        }
        else if (*flag == '6')
        {
            acc_flags |= ACC_MESSAGE_FLAGS_BASE64;
        }
        else if (*flag == 'F')
        {
            acc_flags |= ACC_MESSAGE_FLAGS_FRAGMENT;
        }
        else
        {
            *err_reason = "Unknown flag in flags";
            return -1;
        }
    }
    /* The message should be encoded with exactly one encoding. Ensure that
     * only one of the flags is present */
    bool base64enc = (bool)(acc_flags & ACC_MESSAGE_FLAGS_ASCII);
    bool asciienc = (bool)(acc_flags & ACC_MESSAGE_FLAGS_BASE64);

    if (base64enc + asciienc != 1)
    {
        char *tmp = gc_malloc(512, 1, gc);
        snprintf(tmp, 512, "number of encodings must be exactly one "
                           "(B64=%d, ASCII=%d)",
                 base64enc, asciienc);
        *err_reason = tmp;
        return -1;
    }

    return acc_flags;
}


void
receive_acc_message(struct context *c, const struct buffer *buffer)
{
    struct gc_arena gc = gc_new();
    const char *err_reason = "";

    /* Example message: ACC,muppets,15,A,I am Miss Piggy */
    struct buffer buf = *buffer;

    if (!buf_advance(&buf, strlen("ACC")) || buf_read_u8(&buf) != ',')
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
    if (buf_read_u8(&buf) != U',')
    {
        err_reason = "missing , after payload len";
        goto err;
    }

    int flags = parse_acc_message_flags(&buf, &err_reason, &gc);

    if (flags < 0)
    {
        goto err;
    }

    /* We should have a final NUL byte in the control message buffer
     * and thus the length of the buffer should be payload_len + 1 */
    if (buf_len(&buf) != payload_len + 1)
    {
        char *tmp = gc_malloc(512, 1, &gc);
        snprintf(tmp, 512, "field length %d, payload length %d mismatch",
                 payload_len, buf_len(&buf) - 1);
        err_reason = tmp;
        goto err;
    }


    log_acc_message(c, &buf, payload_len, protocol, flags);
    gc_free(&gc);
    return;

err:
    msg(D_PUSH_ERRORS, "WARNING: Received malformed custom app control channel "
                       "(%s) message control message: %s",
        err_reason,
        format_hex(BPTR(&buf), BLEN(&buf), 80, &gc));
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
