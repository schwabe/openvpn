/*
 *  Interface to ovpn-win-dco networking code
 *
 *  Copyright (C) 2020 Arne Schwabe <arne@rfc2549.org>
 *  Copyright (C) 2020 OpenVPN Inc <sales@openvpn.net>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef OPENVPN_NETWORKING_WINDCO_H
#define OPENVPN_NETWORKING_WINDCO_H
#if defined(ENABLE_WINDCO)
#include "uapi/ovpn-dco.h"
#include "buffer.h"


typedef OVPN_KEY_SLOT ovpn_key_slot_t;

#define DCO_SUPPORTED_CIPHERS "AES-128-GCM:AES-256-GCM:AES-192-GCM"

struct dco_context {
    bool real_tun_init;
};

struct tuntap
dco_create_socket(struct addrinfo *remoteaddr, bool bind_local,
                  struct addrinfo *bind, const char* devname,
                  struct gc_arena *gc, int timeout, volatile int* signal_received);

void dco_start_tun(struct tuntap* tt);

typedef struct dco_context dco_context_t;

#endif
#endif //OPENVPN_NETWORKING_WINDCO_H
