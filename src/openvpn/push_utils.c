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

#ifndef PUSH_UTILS_H
#define PUSH_UTILS_H


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "integer.h"
#include "buffer.h"

/**
 * Extract a field from buf that end with the \c sep character. The
 * returned string is allocated in the gc_arena. If the seperater character
 * is not found, the function returns the nullptr.
 */
char *
extract_field(struct buffer *buf, char sep, struct gc_arena *gc)
{
    const uint8_t *seppos = memchr(BPTR(buf), sep, buf_len(buf));
    if (!seppos)
    {
        return NULL;
    }
    size_t field_len = seppos - BPTR(buf);


    char *field = gc_malloc(field_len + 1, false, gc);
    strncpy(field, BSTR(buf), field_len);

    buf_advance(buf, (int)field_len + 1);
    return field;
}

#endif /* ifndef PUSH_UTILS_H */
