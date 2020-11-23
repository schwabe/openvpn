/*
 *  Interface to linux dco networking code
 *
 *  Copyright (C) 2020 Antonio Quartulli <a@unstable.cc>
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
#ifndef NETWORKING_LINUXDCO_H
#define NETWORKING_LINUXDCO_H
#if defined(ENABLE_LINUXDCO)

#include <netlink/socket.h>
#include <netlink/netlink.h>
#include <linux/ovpn_dco.h>

typedef enum ovpn_key_slot ovpn_key_slot_t;

#include "event.h"

#define DCO_IROUTE_METRIC   100

#define DCO_SUPPORTED_CIPHERS "AES-128-GCM:AES-256-GCM:AES-192-GCM:CHACHA20-POLY1305"

struct dco_context {
    struct nl_sock *nl_sock;
    struct nl_cb *nl_cb;
    int status;

    int ovpn_dco_id;
    int ovpn_dco_mcast_id;

    unsigned int ifindex;

    struct buffer dco_packet_in;

    int dco_message_type;
    int dco_meesage_peer_id;
    int dco_del_peer_reason;

};

typedef struct dco_context dco_context_t;


/**
 * @brief resolves the netlink ID for ovpn-dco
 *
 * This function queries the kernel via a netlink socket
 * whether the ovpn-dco netlink namespace is available
 *
 * This function can be used to determine if the kernel
 * support DCO offloading.
 *
 * @return ID on success, negative error code on error
 */
int
resolve_ovpn_netlink_id(int msglevel);

static inline void
dco_event_set(struct dco_context *dco,
              struct event_set *es,
              void *arg) {
    if (dco && dco->nl_sock) {
        event_ctl(es, nl_socket_get_fd(dco->nl_sock), EVENT_READ, arg);
    }
}

int ovpn_do_write_dco(dco_context_t *dco, int peer_id, struct buffer *buf);

#endif
#endif