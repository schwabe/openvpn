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

#ifndef ACC_H
#define ACC_H

#include "openvpn.h"

#define ACC_MIN_MSG_LEN 64
#define ACC_MAX_MSG_LEN 1280

/**
 * This method parses an app custom control message and delivers it to the
 * management interface. We leave reassembly of fragmented messages to the
 * management interface.
 *
 * @param c            The context struct
 * @param buffer       Buffer containing the control message with ACC
 */
void
receive_acc_message(struct context *c, const struct buffer *buffer);


bool
send_acc_message(struct context *c,
                 struct tls_multi *tls_multi,
                 struct tls_session *session,
                 const char *protocol, bool fragment,
                 const char *msg, bool base64);


/**
 * Parses an info message from the server that contains app custom control info
 * information prior to the PUSH_REPLY to be able to use app custom control
 * protocols before sending
 *
 * In client mode only allow what we support ourselves. In server mode
 * allow also capabilities that we not support ourselves.
 *
 * @param capabilities      The string to parse
 * @param delim             The delimiter to use when parsing the string.
 *                          IV_ACC uses "," as delimiter while the
 *                          custom-control PUSH message uses " " as "," is
 *                          already used to separate different push directives
 * @param max_acc_len       Set to the maximum ACC message length
 * @param server            Whether we are server or client
 * @param gc                The gc arena to use for allocating the resulting string
 * @return                  The resulting protocol string or NULL on error
 */
char *
parse_acc_parameters(const char *capabilities,
                     const char *delim,
                     int *max_acc_len,
                     bool server,
                     struct gc_arena *gc);

/**
 * Parses the IV_ACC of the peer and sets c->options.acc_negotiated_protocols
 * to the common protocols of server and client and
 * c->options.acc_max_message_length  to the maximum length of the ACC message
 * support by both server and client.
 *
 * If there is no common protocol or the client does not support any app custom
 * protocol c->options.acc_negotiated_protocols will be set to NULL.
 *
 * @param c     the client context to use the set the app custom protocols.
 */
void
determine_common_acc_protocols(struct context *c);
#endif
