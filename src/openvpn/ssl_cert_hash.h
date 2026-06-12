/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef SSL_CERT_HASH_H_
#define SSL_CERT_HASH_H_

#include "ssl_common.h"

/**
 * Frees the given set of certificate hashes.
 *
 * @param chs   The certificate hash set to free.
 */
void cert_hash_free(struct cert_hash_set *chs);

/**
 * Locks the certificate hash set used in the given tunnel
 *
 * @param multi The tunnel to lock
 */
void tls_lock_cert_hash_set(struct tls_multi *multi);

#endif /* ifndef SSL_CERT_HASH_H_ */
