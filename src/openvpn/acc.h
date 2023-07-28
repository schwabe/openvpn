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
send_acc_message(struct tls_multi *tls_multi,
                 struct tls_session *session,
                 const char *protocol, bool fragment,
                 const char *msg, bool base64);

#endif
