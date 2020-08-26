/*
 *  Generic interface to platform specific networking code
 *
 *  Copyright (C) 2016-2018 Antonio Quartulli <a@unstable.cc>
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


#ifndef NETWORKING_SITNL_H_
#define NETWORKING_SITNL_H_

typedef char openvpn_net_iface_t;
typedef void *openvpn_net_ctx_t;

/**
 * @brief Add new interface (similar to ip link add)
 *
 * @param iface interface name
 * @param type interface link type (for example "ovpn-dco")
 * @return int 0 on success, negative error code on error
 */
int
net_iface_new(const char *iface, const char *type);

/**
 * @brief Remove an interface (similar to ip link remove)
 *
 * @param iface interface name
 * @return int 0 on success, negative error code on error
 */
int
net_iface_del_name(const char *iface);

/**
 * @brief Remove an interface (similar to ip link remove)
 *
 * @param ifindex interface index
 * @return int 0 on success, negative error code on error
 */
int
net_iface_del_index(int ifindex);

#endif /* NETWORKING_SITNL_H_ */
