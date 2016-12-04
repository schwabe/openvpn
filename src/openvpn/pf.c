/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2016-2017 Antonio Quartulli <a@unstable.cc>
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

/* packet filter functions */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_PF)

#include "init.h"
#include "memdbg.h"
#include "ssl_verify.h"

#include "pf-inline.h"

static void
pf_destroy(struct pf_set *pfs)
{
    if (pfs)
    {
        if (pfs->cns.hash_table)
        {
            hash_free(pfs->cns.hash_table);
        }

        {
            struct pf_cn_elem *l = pfs->cns.list;
            while (l)
            {
                struct pf_cn_elem *next = l->next;
                free(l->rule.cn);
                free(l);
                l = next;
            }
        }
        {
            struct pf_subnet *l = pfs->sns.list;
            while (l)
            {
                struct pf_subnet *next = l->next;
                free(l);
                l = next;
            }
        }
        free(pfs);
    }
}

static bool
add_client(const char *line, const char *prefix, const int line_num, struct pf_cn_elem ***next, const bool exclude)
{
    struct pf_cn_elem *e;
    ALLOC_OBJ_CLEAR(e, struct pf_cn_elem);
    e->rule.exclude = exclude;
    e->rule.cn = string_alloc(line, NULL);
    **next = e;
    *next = &e->next;
    return true;
}

/**
 * Parse line and try to add an IPv6 subnet to the PF subnet list
 *
 * @param line          the line to parse
 * @param prefix        logging prefix
 * @param line_num      line number in the PF file
 * @param div           pointer to the character after the '/', if any
 * @param next          pointer to the location where the next subnet has to be
 *                  stored
 * @param exclude       if true, the opposite of the default policy is applied
 */
static bool
add_subnet_v4(const char *line, const char *prefix, const int line_num,
              const char *div, struct pf_subnet ***next, const bool exclude)
{
    struct in_addr network;
    in_addr_t netmask = 0;
    int netbits = 32;

    if (div)
    {
        if (sscanf(div, "%d", &netbits) != 1)
        {
            msg(D_PF_INFO, "PF: %s/%d: bad '/n' v4 subnet specifier: '%s'",
                prefix, line_num, div);
            return false;
        }
    }

    if ((netbits < 0) || (netbits > 32))
    {
        msg(D_PF_INFO,
            "PF: %s/%d: bad '/n' v4 subnet specifier: must be between 0 and 32: '%s'",
            prefix, line_num, div);
        return false;
    }

    if (openvpn_inet_aton(line, &network) != OIA_IP)
    {
        msg(D_PF_INFO, "PF: %s/%d: bad v4 network address: '%s'", prefix, line_num,
            line);
        return false;
    }

    netmask = netbits_to_netmask(netbits);
    if ((network.s_addr & htonl(netmask)) != network.s_addr)
    {
        network.s_addr &= htonl(netmask);
        msg(M_WARN,
            "WARNING: PF: %s/%d: incorrect v4 subnet %s/%d changed to %s/%d",
            prefix, line_num, line, netbits, inet_ntoa(network), netbits);
    }

    {
        struct pf_subnet *e;
        ALLOC_OBJ_CLEAR(e, struct pf_subnet);
        e->addr_family = AF_INET;
        e->exclude = exclude;
        e->rule.v4.network = ntohl(network.s_addr);
        e->rule.v4.netmask = netmask;
        **next = e;
        *next = &e->next;

        return true;
    }
}

/**
 * Return actual network class based on the specified address and mask
 *
 * @param addr  address to extract the class from
 * @param mask  the network mask
 */
static struct in6_addr
pf_addr_v6_mask(const struct in6_addr *addr, const struct in6_addr *mask)
{
    struct in6_addr res;
    int i;

    for (i = 0; i < sizeof(*addr); i++)
    {
        res.s6_addr[i] = addr->s6_addr[i] & mask->s6_addr[i];
    }

    return res;
}

/**
 * Check if two IPv6 addresses belongs to the same class
 *
 * @param addr1 first address to check
 * @param addr2 second address to check
 * @param mask  netmask to use to extract the IP class
 */
static bool
pf_addr_v6_masked_eq(const struct in6_addr *addr1,
                     const struct in6_addr *addr2,
                     const struct in6_addr *mask)
{
    uint8_t res = 0;
    int i;

    for (i = 0; i < sizeof(*addr1); i++)
    {
        res |= (addr1->s6_addr[i] ^ addr2->s6_addr[i]) & mask->s6_addr[i];
    }

    return res;
}

/**
 * Compare two IPv6 addresses
 *
 * @param addr1 first address to check
 * @param addr2 second address to check
 */
static int
pf_addr_v6_cmp(struct in6_addr *addr1, struct in6_addr *addr2)
{
    return memcmp(addr1, addr2, sizeof(*addr1));
}


/**
 * Parse line and try to add an IPv6 subnet to the PF subnet list
 *
 * @param line          the line to parse
 * @param prefix        logging prefix
 * @param line_num      line number in the PF file/buffer
 * @param div           pointer to the character after the '/', if any
 * @param next          pointer to the location where the next subnet has to be
 *                      stored
 * @param exclude       if true, the opposite of the default policy is applied
 */
static bool
add_subnet_v6(const char *line, const char *prefix, const int line_num,
              const char *div, struct pf_subnet ***next, const bool exclude)

{
    struct in6_addr network, tmp;
    struct in6_addr netmask;
    int netbits = 128;

    if (div)
    {
        if (sscanf(div, "%d", &netbits) != 1)
        {
            msg(D_PF_INFO, "PF: %s/%d: bad '/n' v6 subnet specifier: '%s'",
                prefix, line_num, div);
            return false;
        }
    }

    if ((netbits < 0) || (netbits > 128))
    {
        msg(D_PF_INFO,
            "PF: %s/%d: bad '/n' v6 subnet specifier: must be between 0 and 128: '%s'",
            prefix, line_num, div);
        return false;
    }

    if (openvpn_inet_aton_v6(line, &network) != OIA_IP)
    {
        msg(D_PF_INFO, "PF: %s/%d: bad v6 network address: '%s'", prefix, line_num,
            line);
        return false;
    }

    netmask = netbits_to_netmask_v6(netbits);
    tmp = network;
    network = pf_addr_v6_mask(&network, &netmask);
    if (pf_addr_v6_cmp(&network, &tmp) != 0)
    {
        char v6_str[INET6_ADDRSTRLEN] = {0};

        inet_ntop(AF_INET6, &network, v6_str, INET6_ADDRSTRLEN);
        msg(M_WARN,
            "WARNING: PF: %s/%d: incorrect v6 subnet %s/%d changed to %s/%d",
            prefix, line_num, line, netbits, v6_str, netbits);
    }

    {
        struct pf_subnet *e;
        ALLOC_OBJ_CLEAR(e, struct pf_subnet);
        e->addr_family = AF_INET6;
        e->exclude = exclude;
        e->rule.v6.network = network;
        e->rule.v6.netmask = netmask;
        **next = e;
        *next = &e->next;

        return true;
    }
}

/**
 * Parse line and try to add a subnet to the PF subnet list (either IPv4 or
 * IPv6)
 *
 * @param line          the line to parse
 * @param prefix        some prefix
 * @param line_num      line number in the PF file/buffer
 * @param next          pointer to the location where the next subnet has to be
 *                      stored
 * @param exclude       if true, the opposite of the default policy is applied
 */
static bool
add_subnet(const char *line, const char *prefix, const int line_num,
           struct pf_subnet ***next, const bool exclude)
{
    if (strcmp(line, "unknown") != 0)
    {
        char *div = strchr(line, '/');

        /* if no '/' is found, assume maximum mask */
        if (div)
        {
            *div++ = '\0';
        }

        if (!strchr(line, ':'))
        /* ':' NOT found -> try parsing as IPv4 */
        {
            return add_subnet_v4(line, prefix, line_num, div, next, exclude);
        }
        else
        /* ':' found -> try parsing as IPv6 */
        {
            return add_subnet_v6(line, prefix, line_num, div, next, exclude);
        }
    }
    else
    {
        /* match special "unknown" tag for addresses unrecognized by mroute */
        struct pf_subnet *e;

        ALLOC_OBJ_CLEAR(e, struct pf_subnet);
        e->addr_family = AF_INET;
        e->exclude = exclude;
        e->rule.v4.network = 0;
        e->rule.v4.netmask = IPV4_NETMASK_HOST;
        **next = e;
        *next = &e->next;

        ALLOC_OBJ_CLEAR(e, struct pf_subnet);
        e->addr_family = AF_INET6;
        e->exclude = exclude;
        e->rule.v6.network = in6addr_any;
        e->rule.v6.netmask = in6addr_any;
        **next = e;
        *next = &e->next;
    }

    return true;
}

static uint32_t
cn_hash_function(const void *key, uint32_t iv)
{
    return hash_func((uint8_t *)key, strlen((char *)key) + 1, iv);
}

static bool
cn_compare_function(const void *key1, const void *key2)
{
    return !strcmp((const char *)key1, (const char *)key2);
}

static bool
genhash(struct pf_cn_set *cns, const char *prefix, const int n_clients)
{
    struct pf_cn_elem *e;
    bool status = true;
    int n_buckets = n_clients;

    if (n_buckets < 16)
    {
        n_buckets = 16;
    }
    cns->hash_table = hash_init(n_buckets, 0, cn_hash_function, cn_compare_function);
    for (e = cns->list; e != NULL; e = e->next)
    {
        if (!hash_add(cns->hash_table, e->rule.cn, &e->rule, false))
        {
            msg(D_PF_INFO, "PF: %s: duplicate common name in [clients] section: '%s'", prefix, e->rule.cn);
            status = false;
        }
    }

    return status;
}

static struct pf_set *
pf_init(const struct buffer_list *bl, const char *prefix, const bool allow_kill)
{
#define MODE_UNDEF   0
#define MODE_CLIENTS 1
#define MODE_SUBNETS 2
    int mode = MODE_UNDEF;
    int line_num = 0;
    int n_clients = 0;
    int n_subnets = 0;
    int n_errors = 0;
    struct pf_set *pfs = NULL;
    char line[PF_MAX_LINE_LEN];

    ALLOC_OBJ_CLEAR(pfs, struct pf_set);
    if (bl)
    {
        struct pf_cn_elem **cl = &pfs->cns.list;
        struct pf_subnet **sl = &pfs->sns.list;
        struct buffer_entry *be;

        for (be = bl->head; be != NULL; be = be->next)
        {
            ++line_num;
            strncpynt(line, BSTR(&be->buf), sizeof(line));
            rm_trailing_chars(line, "\r\n\t ");
            if (line[0] == '\0' || line[0] == '#')
            {
            }
            else if (line[0] == '+' || line[0] == '-')
            {
                bool exclude = (line[0] == '-');

                if (line[1] =='\0')
                {
                    msg(D_PF_INFO, "PF: %s/%d: no data after +/-: '%s'", prefix, line_num, line);
                    ++n_errors;
                }
                else if (mode == MODE_CLIENTS)
                {
                    if (add_client(&line[1], prefix, line_num, &cl, exclude))
                    {
                        ++n_clients;
                    }
                    else
                    {
                        ++n_errors;
                    }
                }
                else if (mode == MODE_SUBNETS)
                {
                    if (add_subnet(&line[1], prefix, line_num, &sl, exclude))
                    {
                        ++n_subnets;
                    }
                    else
                    {
                        ++n_errors;
                    }
                }
                else if (mode == MODE_UNDEF)
                {
                }
                else
                {
                    ASSERT(0);
                }
            }
            else if (line[0] == '[')
            {
                if (!strcasecmp(line, "[clients accept]"))
                {
                    mode = MODE_CLIENTS;
                    pfs->cns.default_allow = true;
                }
                else if (!strcasecmp(line, "[clients drop]"))
                {
                    mode = MODE_CLIENTS;
                    pfs->cns.default_allow = false;
                }
                else if (!strcasecmp(line, "[subnets accept]"))
                {
                    mode = MODE_SUBNETS;
                    pfs->sns.default_allow = true;
                }
                else if (!strcasecmp(line, "[subnets drop]"))
                {
                    mode = MODE_SUBNETS;
                    pfs->sns.default_allow = false;
                }
                else if (!strcasecmp(line, "[end]"))
                {
                    goto done;
                }
                else if (allow_kill && !strcasecmp(line, "[kill]"))
                {
                    goto kill;
                }
                else
                {
                    mode = MODE_UNDEF;
                    msg(D_PF_INFO, "PF: %s/%d unknown tag: '%s'", prefix, line_num, line);
                    ++n_errors;
                }
            }
            else
            {
                msg(D_PF_INFO, "PF: %s/%d line must begin with '+', '-', or '[' : '%s'", prefix, line_num, line);
                ++n_errors;
            }
        }
        ++n_errors;
        msg(D_PF_INFO, "PF: %s: missing [end]", prefix);
    }
    else
    {
        msg(D_PF_INFO, "PF: %s: cannot open", prefix);
        ++n_errors;
    }

done:
    if (bl)
    {
        if (!n_errors)
        {
            if (!genhash(&pfs->cns, prefix, n_clients))
            {
                ++n_errors;
            }
        }
        if (n_errors)
        {
            msg(D_PF_INFO, "PF: %s rejected due to %d error(s)", prefix, n_errors);
        }
    }
    if (n_errors)
    {
        pf_destroy(pfs);
        pfs = NULL;
    }
    return pfs;

kill:
    pf_destroy(pfs);
    ALLOC_OBJ_CLEAR(pfs, struct pf_set);
    pfs->kill = true;
    return pfs;
}

#ifdef PLUGIN_PF
static struct pf_set *
pf_init_from_file(const char *fn)
{
    struct buffer_list *bl = buffer_list_file(fn, PF_MAX_LINE_LEN);
    if (bl)
    {
        struct pf_set *pfs = pf_init(bl, fn, true);
        buffer_list_free(bl);
        return pfs;
    }
    else
    {
        msg(D_PF_INFO|M_ERRNO, "PF: %s: cannot open", fn);
        return NULL;
    }
}
#endif

#ifdef ENABLE_DEBUG

static const char *
drop_accept(const bool accept)
{
    return accept ? "ACCEPT" : "DROP";
}

static const char *
pct_name(const int type)
{
    switch (type)
    {
        case PCT_SRC:
            return "SRC";

        case PCT_DEST:
            return "DEST";

        default:
            return "???";
    }
}

static void
pf_cn_test_print(const char *prefix,
                 const int type,
                 const char *prefix2,
                 const char *cn,
                 const bool allow,
                 const struct pf_cn *rule)
{
    if (rule)
    {
        dmsg(D_PF_DEBUG, "PF: %s/%s/%s %s %s rule=[%s %s]",
             prefix, prefix2, pct_name(type),
             cn, drop_accept(allow),
             rule->cn, drop_accept(!rule->exclude));
    }
    else
    {
        dmsg(D_PF_DEBUG, "PF: %s/%s/%s %s %s",
             prefix, prefix2, pct_name(type),
             cn, drop_accept(allow));
    }
}

static void
pf_addr_test_print(const char *prefix, const char *prefix2,
                   const struct context *src, const struct mroute_addr *dest,
                   const bool allow, const struct pf_subnet *subnet)
{
    struct gc_arena gc = gc_new();
    const char *network, *netmask;

    if (subnet)
    {
        switch (subnet->addr_family)
        {
            case AF_INET:
                network = print_in_addr_t(subnet->rule.v4.network, 0, &gc);
                netmask = print_in_addr_t(subnet->rule.v4.netmask, 0, &gc);
                break;
            case AF_INET6:
                network = print_in6_addr(subnet->rule.v6.network, 0, &gc);
                netmask = print_in6_addr(subnet->rule.v6.netmask, 0, &gc);
                break;
            default:
                return;
        }


        dmsg(D_PF_DEBUG, "PF: %s/%s %s %s %s rule=[%s/%s %s]",
             prefix,
             prefix2,
             tls_common_name(src->c2.tls_multi, false),
             mroute_addr_print_ex(dest, MAPF_SHOW_ARP, &gc),
             drop_accept(allow), network, netmask,
             drop_accept(!subnet->exclude));
    }
    else
    {
        dmsg(D_PF_DEBUG, "PF: %s/%s %s %s %s",
             prefix,
             prefix2,
             tls_common_name(src->c2.tls_multi, false),
             mroute_addr_print_ex(dest, MAPF_SHOW_ARP, &gc),
             drop_accept(allow));
    }
    gc_free(&gc);
}

#endif /* ifdef ENABLE_DEBUG */

static inline struct pf_cn *
lookup_cn_rule(struct hash *h, const char *cn, const uint32_t cn_hash)
{
    struct hash_element *he = hash_lookup_fast(h, hash_bucket(h, cn_hash), cn, cn_hash);
    if (he)
    {
        return (struct pf_cn *) he->value;
    }
    else
    {
        return NULL;
    }
}

bool
pf_cn_test(struct pf_set *pfs, const struct tls_multi *tm, const int type, const char *prefix)
{
    if (pfs && !pfs->kill)
    {
        const char *cn;
        uint32_t cn_hash;
        if (tls_common_name_hash(tm, &cn, &cn_hash))
        {
            const struct pf_cn *rule = lookup_cn_rule(pfs->cns.hash_table, cn, cn_hash);
            if (rule)
            {
#ifdef ENABLE_DEBUG
                if (check_debug_level(D_PF_DEBUG))
                {
                    pf_cn_test_print("PF_CN_MATCH", type, prefix, cn, !rule->exclude, rule);
                }
#endif
                if (!rule->exclude)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
#ifdef ENABLE_DEBUG
                if (check_debug_level(D_PF_DEBUG))
                {
                    pf_cn_test_print("PF_CN_DEFAULT", type, prefix, cn, pfs->cns.default_allow, NULL);
                }
#endif
                if (pfs->cns.default_allow)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }
    }
#ifdef ENABLE_DEBUG
    if (check_debug_level(D_PF_DEBUG))
    {
        pf_cn_test_print("PF_CN_FAULT", type, prefix, tls_common_name(tm, false), false, NULL);
    }
#endif
    return false;
}

/**
 * Check if the IPv4 source address matches against the subnet rules
 *
 * @param src           the packet source IPv4 address
 * @param dest          the packet destination IPv4 address
 * @param prefix        logging prefix
 */
bool
pf_addr_v4_test_dowork(const struct context *src,
                       const struct mroute_addr *dest, const char *prefix)
{
    const in_addr_t addr = in_addr_t_from_mroute_addr(dest);
    struct pf_set *pfs = src->c2.pf.pfs;
    const struct pf_subnet *se = pfs->sns.list;

    while (se)
    {
#ifdef ENABLE_DEBUG
        if (check_debug_level(D_PF_DEBUG))
        {
            pf_addr_test_print("PF_ADDR_CHECK", prefix, src, dest, !se->exclude,
                               se);
        }
#endif
        if ((se->addr_family == AF_INET)
            && (addr & se->rule.v4.netmask) == se->rule.v4.network)
        {
#ifdef ENABLE_DEBUG
            if (check_debug_level(D_PF_DEBUG))
            {
                pf_addr_test_print("PF_ADDR_MATCH", prefix, src, dest,
                                   !se->exclude, se);
            }
#endif
            return !se->exclude;
        }
        se = se->next;
    }
#ifdef ENABLE_DEBUG
    if (check_debug_level(D_PF_DEBUG))
    {
        pf_addr_test_print("PF_ADDR_DEFAULT", prefix, src, dest,
                           pfs->sns.default_allow, NULL);
    }
#endif
    return pfs->sns.default_allow;
}

/**
 * Check if the IPv6 source address matches against the subnet rules
 *
 * @param src           the packet source IPv6 address
 * @param dest          the packet destination IPv6 address
 * @param prefix        logging prefix
 */
bool
pf_addr_v6_test_dowork(const struct context *src,
                       const struct mroute_addr *dest, const char *prefix)
{
    const struct in6_addr addr = in6_addr_from_mroute_addr(dest);
    struct pf_set *pfs = src->c2.pf.pfs;
    const struct pf_subnet *se = pfs->sns.list;

    while (se)
    {
#ifdef ENABLE_DEBUG
        if (check_debug_level(D_PF_DEBUG))
        {
            pf_addr_test_print("PFv6_ADDR_CHECK", prefix, src, dest, !se->exclude,
                               se);
        }
#endif
        if ((se->addr_family == AF_INET6)
            && (pf_addr_v6_masked_eq(&addr, &se->rule.v6.network,
                                     &se->rule.v6.netmask) == 0))
        {
#ifdef ENABLE_DEBUG
            if (check_debug_level(D_PF_DEBUG))
            {
                pf_addr_test_print("PFv6_ADDR_MATCH", prefix, src, dest,
                                   !se->exclude, se);
            }
#endif
            return !se->exclude;
        }
        se = se->next;
    }
#ifdef ENABLE_DEBUG
    if (check_debug_level(D_PF_DEBUG))
    {
        pf_addr_test_print("PFv6_ADDR_DEFAULT", prefix, src, dest,
                           pfs->sns.default_allow, NULL);
    }
#endif
    return pfs->sns.default_allow;
}

/**
 * Check if the source address matches against the subnet rules (either IPv4
 * or IPv6)
 *
 * @param src           the packet source address
 * @param dest          the packet destination address
 * @param prefix        logging prefix
 */
bool
pf_addr_test_dowork(const struct context *src, const struct mroute_addr *dest,
                    const char *prefix)
{
    struct pf_set *pfs = src->c2.pf.pfs;

    if (pfs && !pfs->kill)
    {
        bool ret = true;

        msg(D_PF_DEBUG, "PF: packet_type: %d", dest->type & MR_ADDR_MASK);
        switch (dest->type & MR_ADDR_MASK)
        {
            case MR_ADDR_IPV4:
                ret = pf_addr_v4_test_dowork(src, dest, prefix);
                break;

            case MR_ADDR_IPV6:
                ret = pf_addr_v6_test_dowork(src, dest, prefix);
                break;

            default:
                /* ignore non-IP traffic */
                break;
        }
        return ret;
    }
    else
    {
#ifdef ENABLE_DEBUG
        if (check_debug_level(D_PF_DEBUG))
        {
            pf_addr_test_print("PF_ADDR_FAULT", prefix, src, dest, false, NULL);
        }
#endif
    }

    return false;
}

#ifdef PLUGIN_PF
void
pf_check_reload(struct context *c)
{
    const int slow_wakeup = 15;
    const int fast_wakeup = 1;
    const int wakeup_transition = 60;
    bool reloaded = false;

    if (c->c2.pf.enabled
        && c->c2.pf.filename
        && event_timeout_trigger(&c->c2.pf.reload, &c->c2.timeval, ETT_DEFAULT))
    {
        platform_stat_t s;
        if (!platform_stat(c->c2.pf.filename, &s))
        {
            if (s.st_mtime > c->c2.pf.file_last_mod)
            {
                struct pf_set *pfs = pf_init_from_file(c->c2.pf.filename);
                if (pfs)
                {
                    if (c->c2.pf.pfs)
                    {
                        pf_destroy(c->c2.pf.pfs);
                    }
                    c->c2.pf.pfs = pfs;
                    reloaded = true;
                    if (pf_kill_test(pfs))
                    {
                        c->sig->signal_received = SIGTERM;
                        c->sig->signal_text = "pf-kill";
                    }
                }
                c->c2.pf.file_last_mod = s.st_mtime;
            }
        }
        {
            int wakeup = slow_wakeup;
            if (!c->c2.pf.pfs && c->c2.pf.n_check_reload < wakeup_transition)
            {
                wakeup = fast_wakeup;
            }
            event_timeout_init(&c->c2.pf.reload, wakeup, now);
            reset_coarse_timers(c);
            c->c2.pf.n_check_reload++;
        }
    }
#ifdef ENABLE_DEBUG
    if (reloaded && check_debug_level(D_PF_DEBUG))
    {
        pf_context_print(&c->c2.pf, "pf_check_reload", D_PF_DEBUG);
    }
#endif
}
#endif /* ifdef PLUGIN_PF */

#ifdef MANAGEMENT_PF
bool
pf_load_from_buffer_list(struct context *c, const struct buffer_list *config)
{
    struct pf_set *pfs = pf_init(config, "[SERVER-PF]", false);
    if (pfs)
    {
        if (c->c2.pf.pfs)
        {
            pf_destroy(c->c2.pf.pfs);
        }
        c->c2.pf.pfs = pfs;
        return true;
    }
    else
    {
        return false;
    }
}
#endif

void
pf_init_context(struct context *c)
{
    struct gc_arena gc = gc_new();
#ifdef PLUGIN_PF
    if (plugin_defined(c->plugins, OPENVPN_PLUGIN_ENABLE_PF))
    {
        const char *pf_file = create_temp_file(c->options.tmp_dir, "pf", &gc);
        if (pf_file)
        {
            setenv_str(c->c2.es, "pf_file", pf_file);

            if (plugin_call(c->plugins, OPENVPN_PLUGIN_ENABLE_PF, NULL, NULL, c->c2.es) == OPENVPN_PLUGIN_FUNC_SUCCESS)
            {
                event_timeout_init(&c->c2.pf.reload, 1, now);
                c->c2.pf.filename = string_alloc(pf_file, &c->c2.gc);
                c->c2.pf.enabled = true;
#ifdef ENABLE_DEBUG
                if (check_debug_level(D_PF_DEBUG))
                {
                    pf_context_print(&c->c2.pf, "pf_init_context#1", D_PF_DEBUG);
                }
#endif
            }
            else
            {
                msg(M_WARN, "WARNING: OPENVPN_PLUGIN_ENABLE_PF disabled");
            }
        }
    }
#endif /* ifdef PLUGIN_PF */
#ifdef MANAGEMENT_PF
    if (!c->c2.pf.enabled && management_enable_pf(management))
    {
        c->c2.pf.enabled = true;
#ifdef ENABLE_DEBUG
        if (check_debug_level(D_PF_DEBUG))
        {
            pf_context_print(&c->c2.pf, "pf_init_context#2", D_PF_DEBUG);
        }
#endif
    }
#endif
    gc_free(&gc);
}

void
pf_destroy_context(struct pf_context *pfc)
{
#ifdef PLUGIN_PF
    if (pfc->filename)
    {
        platform_unlink(pfc->filename);
    }
#endif
    if (pfc->pfs)
    {
        pf_destroy(pfc->pfs);
    }
}

#ifdef ENABLE_DEBUG

static void
pf_subnet_set_print(const struct pf_subnet_set *s, const int lev)
{
    struct gc_arena gc = gc_new();
    if (s)
    {
        struct pf_subnet *e;

        msg(lev, "  ----- struct pf_subnet_set -----");
        msg(lev, "  default_allow=%s", drop_accept(s->default_allow));

        for (e = s->list; e != NULL; e = e->next)
        {
            if (e->addr_family == AF_INET)
            {
                msg(lev, "   %s/%s %s",
                    print_in_addr_t(e->rule.v4.network, 0, &gc),
                    print_in_addr_t(e->rule.v4.netmask, 0, &gc),
                    drop_accept(!e->exclude));
            }
            else
            {
                msg(lev, "   %s/%s %s",
                    print_in6_addr(e->rule.v6.network, 0, &gc),
                    print_in6_addr(e->rule.v6.netmask, 0, &gc),
                    drop_accept(!e->exclude));
            }
        }
    }
    gc_free(&gc);
}

static void
pf_cn_set_print(const struct pf_cn_set *s, const int lev)
{
    if (s)
    {
        struct hash_iterator hi;
        struct hash_element *he;

        msg(lev, "  ----- struct pf_cn_set -----");
        msg(lev, "  default_allow=%s", drop_accept(s->default_allow));

        if (s->hash_table)
        {
            hash_iterator_init(s->hash_table, &hi);
            while ((he = hash_iterator_next(&hi)))
            {
                struct pf_cn *e = (struct pf_cn *)he->value;
                msg(lev, "   %s %s",
                    e->cn,
                    drop_accept(!e->exclude));
            }

            msg(lev, "  ----------");

            {
                struct pf_cn_elem *ce;
                for (ce = s->list; ce != NULL; ce = ce->next)
                {
                    struct pf_cn *e = lookup_cn_rule(s->hash_table, ce->rule.cn, cn_hash_function(ce->rule.cn, 0));
                    if (e)
                    {
                        msg(lev, "   %s %s",
                            e->cn,
                            drop_accept(!e->exclude));
                    }
                    else
                    {
                        msg(lev, "   %s LOOKUP FAILED", ce->rule.cn);
                    }
                }
            }
        }
    }
}

static void
pf_set_print(const struct pf_set *pfs, const int lev)
{
    if (pfs)
    {
        msg(lev, " ----- struct pf_set -----");
        msg(lev, " kill=%d", pfs->kill);
        pf_subnet_set_print(&pfs->sns, lev);
        pf_cn_set_print(&pfs->cns, lev);
    }
}

void
pf_context_print(const struct pf_context *pfc, const char *prefix, const int lev)
{
    msg(lev, "----- %s : struct pf_context -----", prefix);
    if (pfc)
    {
        msg(lev, "enabled=%d", pfc->enabled);
#ifdef PLUGIN_PF
        msg(lev, "filename='%s'", np(pfc->filename));
        msg(lev, "file_last_mod=%u", (unsigned int)pfc->file_last_mod);
        msg(lev, "n_check_reload=%u", pfc->n_check_reload);
        msg(lev, "reload=[%d,%u,%u]", pfc->reload.defined, pfc->reload.n, (unsigned int)pfc->reload.last);
#endif
        pf_set_print(pfc->pfs, lev);
    }
    msg(lev, "--------------------");
}

#endif /* ifdef ENABLE_DEBUG */

#endif /* if defined(ENABLE_PF) */
