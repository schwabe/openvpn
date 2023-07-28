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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "acc.h"
#include "test_acc.h"

#include "mock_msg.h"

/* Mock functions */
bool
send_control_channel_string_dowork(struct tls_session *session,
                                   const char *str, int msglevel)
{
    assert_false(true);
    return false;
}

void
send_push_reply_auth_token(struct tls_multi *multi)
{
}

void
auth_set_client_reason(struct tls_multi *multi, const char *reason)
{
}

#define MSG_PAYLOAD "FgMBARkBAAEVAwNanUalkEDDxLBpZw9JnjI3tBM"                \
                    "r4engpg/cDgS48DMaxyCdbzofNjQJU9Y0DD66z/notFT0cF1d60nTS" \
                    "4md4OJwoQAwEwITAxMBwCzAMACfzKnMqMyqwCvALwCewCTAKABrwCP" \
                    "AJwBnwArAFAA5wAnAEwAzAQAAnP8BAAEAAAsABAMAAQIACgAWABQAH" \
                    "QAXAB4AGQAYAQABAQECAQMBBAAWAAAAFwAAAA0AMAAuBAMFAwYDCAc" \
                    "ICAgaCBsIHAgJCAoICwgECAUIBgQBBQEGAQMDAwEDAgQCBQIGAgArA" \
                    "AUEAwQDAwAtAAIBAQAzACYAJAAdACCk4Tz2PB/2FsxOfOIV4gn/NyJ" \
                    "93rQwityP9eKSijXgcQ=="

void
test_acc_parse_client_messages(void **state)
{
    /* ensure that the messages get to mock_msg */
    x_debug_level = 3;
    management = (void *)0x12345678;
    struct gc_arena gc = gc_new();

    /* contains a TLS 1.3 ClientHello */
    const char msg[] = "ACC,cck1,384,6," MSG_PAYLOAD;

    struct buffer msg_buf;
    struct context c = { 0 };

    ALLOC_OBJ_CLEAR_GC(c.c2.tls_multi, struct tls_multi, &gc);
    ALLOC_OBJ_CLEAR_GC(c.c2.tls_multi, struct tls_multi, &gc);

    c.c2.tls_multi->session[TM_ACTIVE].opt = &c.c2.tls_multi->opt;
    c.c2.tls_multi->session[TM_ACTIVE].opt->mda_context = &c.c2.mda_context;
    buf_set_read(&msg_buf, (void *)msg, sizeof(msg));
    receive_acc_message(&c, &msg_buf);

    assert_string_equal(mock_msg_buf, "custom app control message (protocol 'cck1', fragment 0)");
    assert_string_equal(mock_managment_buf, ">CLIENT:ACC,0,0,cck1,0," MSG_PAYLOAD);

    const char flower_msg[] = "ACC,flower,48,6,SSBhbSAAIEtlcm1pdCD//SB0aGUg77+94oCPZnJvZyEAAA==";
    buf_set_read(&msg_buf, (void *)flower_msg, sizeof(flower_msg));
    receive_acc_message(&c, &msg_buf);
    assert_string_equal(mock_msg_buf, "custom app control message (protocol 'flower', fragment 0)");
    assert_string_equal(mock_managment_buf, ">CLIENT:ACC,0,0,flower,0,SSBhbSAAIEtlcm1pdCD//SB0aGUg77+94oCPZnJvZyEAAA==");

    CLEAR(mock_managment_buf);
    const char msg_incorrect_len[] = "ACC,fortune,62,6,InsgIm1lIjogImZyb2ciLCAAeGZm/SJtc2ciOiAiSSBhbSAAS2VybWl0IiB9Ig==";
    buf_set_read(&msg_buf, (void *)msg_incorrect_len, sizeof(msg_incorrect_len));
    receive_acc_message(&c, &msg_buf);
    const char *error = "WARNING: Received malformed custom app control channel "
                        "(field length 62, payload length 64 mismatch) message "
                        "control message: 496e7367 496d316c 496a6f67 496d5a79 "
                        "62326369 4c434141 65475a6d 2f534a7[more...]";

    assert_string_equal(mock_msg_buf, error);
    assert_string_equal(mock_managment_buf, "");

    /* check two encoding present */
    const char flower_msg_two_encs[] = "ACC,flower,48,6A,SSBhbSAAIEtlcm1pdCD//SB0aGUg77+94oCPZnJvZyEAAA==";
    buf_set_read(&msg_buf, (void *)flower_msg_two_encs, sizeof(flower_msg_two_encs));
    receive_acc_message(&c, &msg_buf);

    error = "WARNING: Received malformed custom app control channel (number of "
            "encodings must be exactly one (B64=1, ASCII=1)) message control "
            "message: 53534268 62534141 4945746c 636d3170 6443442f 2f534230 "
            "61475567 37372b3[more...]";
    assert_string_equal(mock_msg_buf, error);
    assert_string_equal(mock_managment_buf, "");

    /* no encoding present */
    const char flower_msg_no_encs[] = "ACC,flower,48,,SSBhbSAAIEtlcm1pdCD//SB0aGUg77+94oCPZnJvZyEAAA==";
    buf_set_read(&msg_buf, (void *)flower_msg_no_encs, sizeof(flower_msg_no_encs));
    receive_acc_message(&c, &msg_buf);

    error = "WARNING: Received malformed custom app control channel (number of "
            "encodings must be exactly one (B64=0, ASCII=0)) message control "
            "message: 53534268 62534141 4945746c 636d3170 6443442f 2f534230 "
            "61475567 37372b3[more...]";
    assert_string_equal(mock_msg_buf, error);
    assert_string_equal(mock_managment_buf, "");

    x_debug_level = 0;
    management = NULL;
    gc_free(&gc);
}
