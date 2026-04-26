#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>

#define BUF_SIZE 32768
#define MAX_INTERFACES 256

// GLOBAL FILTER: Moved to the top so parsing functions can access it
static int af_filter = AF_UNSPEC;

// ===================== NETLINK HELPERS =====================

static int nl_send(int sock, struct nlmsghdr *nlh) {
    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
    struct iovec iov = { .iov_base = nlh, .iov_len = nlh->nlmsg_len };
    struct msghdr msg = {
        .msg_name = &addr,
        .msg_namelen = sizeof(addr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    return sendmsg(sock, &msg, 0);
}

// ===================== LINK =====================

static void ip_link_show(const char *filter_dev) {
    struct ifaddrs *ifaddr, *ifa;
    char seen[MAX_INTERFACES][IFNAMSIZ];
    int seen_count = 0;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == NULL)
            continue;

        if (filter_dev && strlen(filter_dev) > 0 && strcmp(filter_dev, ifa->ifa_name) != 0)
            continue;

        /* Check if already processed */
        int already_seen = 0;
        for (int i = 0; i < seen_count; i++) {
            if (strncmp(seen[i], ifa->ifa_name, IFNAMSIZ) == 0) {
                already_seen = 1;
                break;
            }
        }

        if (already_seen)
            continue;

        /* Add to seen list */
        if (seen_count < MAX_INTERFACES) {
            strncpy(seen[seen_count], ifa->ifa_name, IFNAMSIZ - 1);
            seen[seen_count][IFNAMSIZ - 1] = '\0';
            seen_count++;
        }

        /* Optimized Output formatting */
        printf("%s: <", ifa->ifa_name);
        int first = 1;
        unsigned int flags = ifa->ifa_flags;
        
        #define PFLAG(f, name) if (flags & f) { if (!first) printf(","); printf(name); first = 0; }
        PFLAG(IFF_UP, "UP")
        PFLAG(IFF_BROADCAST, "BROADCAST")
        PFLAG(IFF_DEBUG, "DEBUG")
        PFLAG(IFF_LOOPBACK, "LOOPBACK")
        PFLAG(IFF_POINTOPOINT, "POINTOPOINT")
        PFLAG(IFF_RUNNING, "RUNNING")
        PFLAG(IFF_NOARP, "NOARP")
        PFLAG(IFF_PROMISC, "PROMISC")
        PFLAG(IFF_MULTICAST, "MULTICAST")
        #undef PFLAG
        
        printf(">\n");
    }

    freeifaddrs(ifaddr);
}

// ===================== ROUTE =====================

static const char *get_table_name(uint32_t id) {
    switch (id) {
        case RT_TABLE_UNSPEC: return "unspec";
        case RT_TABLE_COMPAT: return "compat";
        case RT_TABLE_DEFAULT: return "default";
        case RT_TABLE_MAIN: return "main";
        case RT_TABLE_LOCAL: return "local";
        default: return NULL;
    }
}

static const char *get_proto_name(unsigned char proto) {
    switch (proto) {
        case RTPROT_UNSPEC: return "unspec";
        case RTPROT_REDIRECT: return "redirect";
        case RTPROT_KERNEL: return "kernel";
        case RTPROT_BOOT: return "boot";
        case RTPROT_STATIC: return "static";
#ifdef RTPROT_GATED
        case RTPROT_GATED: return "gated";
#endif
#ifdef RTPROT_RA
        case RTPROT_RA: return "ra";
#endif
#ifdef RTPROT_MRT
        case RTPROT_MRT: return "mrt";
#endif
#ifdef RTPROT_ZEBRA
        case RTPROT_ZEBRA: return "zebra";
#endif
#ifdef RTPROT_BIRD
        case RTPROT_BIRD: return "bird";
#endif
#ifdef RTPROT_DNROUTED
        case RTPROT_DNROUTED: return "dnrouted";
#endif
#ifdef RTPROT_XORP
        case RTPROT_XORP: return "xorp";
#endif
#ifdef RTPROT_NTK
        case RTPROT_NTK: return "ntk";
#endif
#ifdef RTPROT_DHCP
        case RTPROT_DHCP: return "dhcp";
#endif
#ifdef RTPROT_MROUTED
        case RTPROT_MROUTED: return "mrouted";
#endif
#ifdef RTPROT_BABEL
        case RTPROT_BABEL: return "babel";
#endif
        default: return NULL;
    }
}

static void parse_route(struct nlmsghdr *nlh, const char *filter_dev) {
    struct rtmsg *rtm = NLMSG_DATA(nlh);

    if (af_filter != AF_UNSPEC && rtm->rtm_family != af_filter)
        return;
    struct rtattr *rta = RTM_RTA(rtm);
    int rtl = RTM_PAYLOAD(nlh);

    char dst[INET6_ADDRSTRLEN] = "";
    char gw[INET6_ADDRSTRLEN] = "";
    char dev[IF_NAMESIZE] = "";
    
    // Fetch initial table ID from route message header
    uint32_t table_id = rtm->rtm_table;

    for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
        switch (rta->rta_type) {
            case RTA_DST:
                inet_ntop(rtm->rtm_family, RTA_DATA(rta), dst, sizeof(dst));
                break;
            case RTA_GATEWAY:
                inet_ntop(rtm->rtm_family, RTA_DATA(rta), gw, sizeof(gw));
                break;
            case RTA_OIF: {
                int idx;
                memcpy(&idx, RTA_DATA(rta), sizeof(idx));
                if_indextoname(idx, dev);
                break;
            }
            case RTA_TABLE: {
                // Extended table ID (takes priority over rtm->rtm_table)
                memcpy(&table_id, RTA_DATA(rta), sizeof(table_id));
                break;
            }
        }
    }

    if (filter_dev && strlen(filter_dev) > 0 && strcmp(filter_dev, dev) != 0)
        return;

    if (strlen(dst) == 0)
        printf("default ");
    else
        printf("%s/%d ", dst, rtm->rtm_dst_len);

    if (strlen(gw))
        printf("via %s ", gw);

    if (strlen(dev))
        printf("dev %s ", dev);

    // Print out the protocol
    const char *proto_name = get_proto_name(rtm->rtm_protocol);
    if (proto_name)
        printf("proto %s ", proto_name);
    else
        printf("proto %u ", rtm->rtm_protocol);

    // Print out the table ID
    const char *table_name = get_table_name(table_id);
    if (table_name)
        printf("table %s\n", table_name);
    else
        printf("table %u\n", table_id);
}

static void ip_route_show(const char *dev) {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) { perror("socket"); return; }

    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } req = {0};

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;

    req.rtm.rtm_family = af_filter;

    if (nl_send(sock, &req.nlh) < 0) {
        perror("sendmsg"); close(sock); return;
    }

    char buf[BUF_SIZE];

    while (1) {
        int len = recv(sock, buf, sizeof(buf), 0);
        if (len < 0) { perror("recv"); break; }

        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

        for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_seq != 1) continue;

            if (nlh->nlmsg_type == NLMSG_DONE) {
                close(sock);
                return;
            }

            if (nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = NLMSG_DATA(nlh);
                errno = -err->error;
                perror("netlink");
                close(sock);
                return;
            }

            if (nlh->nlmsg_type == RTM_NEWROUTE)
                parse_route(nlh, dev);
        }
    }

    close(sock);
}

// ===================== ADDR =====================

static void parse_addr(struct nlmsghdr *nlh, const char *filter_dev) {
    struct ifaddrmsg *ifa = NLMSG_DATA(nlh);

    if (af_filter != AF_UNSPEC && ifa->ifa_family != af_filter)
        return;
    struct rtattr *rta = IFA_RTA(ifa);
    int rtl = IFA_PAYLOAD(nlh);

    char addr[INET6_ADDRSTRLEN] = "";
    char dev[IF_NAMESIZE] = "";

    if_indextoname(ifa->ifa_index, dev);

    for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
        if (rta->rta_type == IFA_ADDRESS || rta->rta_type == IFA_LOCAL) {
            inet_ntop(ifa->ifa_family, RTA_DATA(rta), addr, sizeof(addr));
        }
    }

    if (filter_dev && strcmp(filter_dev, dev) != 0)
        return;

    if (strlen(addr))
        printf("%s %s/%d\n", dev, addr, ifa->ifa_prefixlen);
}

static void ip_addr_show(const char *dev) {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) { perror("socket"); return; }

    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
    } req = {0};

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nlh.nlmsg_type = RTM_GETADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 2;

    req.ifa.ifa_family = af_filter;

    if (nl_send(sock, &req.nlh) < 0) {
        perror("sendmsg"); close(sock); return;
    }

    char buf[BUF_SIZE];

    while (1) {
        int len = recv(sock, buf, sizeof(buf), 0);
        if (len < 0) { perror("recv"); break; }

        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

        for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_seq != 2) continue;

            if (nlh->nlmsg_type == NLMSG_DONE) {
                close(sock);
                return;
            }

            if (nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = NLMSG_DATA(nlh);
                errno = -err->error;
                perror("netlink");
                close(sock);
                return;
            }

            if (nlh->nlmsg_type == RTM_NEWADDR)
                parse_addr(nlh, dev);
        }
    }

    close(sock);
}

// ===================== NEIGHBOR =====================

static void parse_neigh(struct nlmsghdr *nlh, const char *filter_dev) {
    struct ndmsg *ndm = NLMSG_DATA(nlh);

    if (af_filter != AF_UNSPEC && ndm->ndm_family != af_filter)
        return;

    int attr_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ndm));
    struct rtattr *rta = (struct rtattr *)((char *)ndm + NLMSG_ALIGN(sizeof(*ndm)));

    struct rtattr *tb[NDA_MAX + 1];
    memset(tb, 0, sizeof(tb));

    while (RTA_OK(rta, attr_len)) {
        if (rta->rta_type <= NDA_MAX)
            tb[rta->rta_type] = rta;
        rta = RTA_NEXT(rta, attr_len);
    }

    char ip[INET6_ADDRSTRLEN] = {0};
    char ifname[IF_NAMESIZE] = {0};

    if_indextoname(ndm->ndm_ifindex, ifname);

    if (filter_dev && strlen(filter_dev) > 0 && strcmp(filter_dev, ifname) != 0)
        return;

    if (tb[NDA_DST]) {
        if (ndm->ndm_family == AF_INET) {
            inet_ntop(AF_INET, RTA_DATA(tb[NDA_DST]), ip, sizeof(ip));
        } else if (ndm->ndm_family == AF_INET6) {
            inet_ntop(AF_INET6, RTA_DATA(tb[NDA_DST]), ip, sizeof(ip));
        }
    }

    if (ip[0]) 
        printf("%s ", ip);
        
    printf("dev %s ", ifname[0] ? ifname : "?");

    if (tb[NDA_LLADDR]) {
        unsigned char *mac = RTA_DATA(tb[NDA_LLADDR]);
        int maclen = RTA_PAYLOAD(tb[NDA_LLADDR]);

        printf("lladdr ");
        for (int i = 0; i < maclen; i++) {
            printf("%02x%s", mac[i], (i + 1 < maclen) ? ":" : "");
        }
        printf(" ");
    }

    if (ndm->ndm_flags & NTF_ROUTER)
        printf("router ");

    // Map common neighbor states to standard ip output
    if (ndm->ndm_state & NUD_PERMANENT) printf("PERMANENT ");
    else if (ndm->ndm_state & NUD_NOARP) printf("NOARP ");
    else if (ndm->ndm_state & NUD_REACHABLE) printf("REACHABLE ");
    else if (ndm->ndm_state & NUD_STALE) printf("STALE ");
    else if (ndm->ndm_state & NUD_DELAY) printf("DELAY ");
    else if (ndm->ndm_state & NUD_PROBE) printf("PROBE ");
    else if (ndm->ndm_state & NUD_FAILED) printf("FAILED ");
    else if (ndm->ndm_state & NUD_INCOMPLETE) printf("INCOMPLETE ");
    else if (ndm->ndm_state == NUD_NONE) printf("NONE ");
    else printf("state 0x%x ", ndm->ndm_state);

    printf("\n");
}

static void ip_neigh_show(const char *dev) {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) { perror("socket"); return; }

    struct {
        struct nlmsghdr nlh;
        struct ndmsg ndm;
    } req = {0};

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.nlh.nlmsg_type = RTM_GETNEIGH;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 3; // Distinct sequence ID

    req.ndm.ndm_family = af_filter;

    if (nl_send(sock, &req.nlh) < 0) {
        perror("sendmsg"); close(sock); return;
    }

    char buf[BUF_SIZE];

    while (1) {
        int len = recv(sock, buf, sizeof(buf), 0);
        if (len < 0) { perror("recv"); break; }

        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

        for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_seq != 3) continue;

            if (nlh->nlmsg_type == NLMSG_DONE) {
                close(sock);
                return;
            }

            if (nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = NLMSG_DATA(nlh);
                if (err->error) errno = -err->error;
                perror("netlink");
                close(sock);
                return;
            }

            if (nlh->nlmsg_type == RTM_NEWNEIGH)
                parse_neigh(nlh, dev);
        }
    }

    close(sock);
}


// ===================== MAIN =====================

int main(int argc, char *argv[]) {
    int argi = 1;

    // Parse optional -4 / -6
    if (argc > 1) {
        if (strcmp(argv[argi], "-4") == 0) {
            af_filter = AF_INET;
            argi++;
        } else if (strcmp(argv[argi], "-6") == 0) {
            af_filter = AF_INET6;
            argi++;
        }
    }

    if (argc - argi < 2) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s [-4|-6] link show [dev]\n", argv[0]);
        fprintf(stderr, "  %s [-4|-6] route show [dev]\n", argv[0]);
        fprintf(stderr, "  %s [-4|-6] addr show [dev]\n", argv[0]);
        fprintf(stderr, "  %s [-4|-6] neigh show [dev]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[argi], "link") == 0 && strcmp(argv[argi+1], "show") == 0) {
        const char *dev = (argc - argi >= 3) ? argv[argi+2] : NULL;
        ip_link_show(dev);
    } else if (strcmp(argv[argi], "route") == 0 && strcmp(argv[argi+1], "show") == 0) {
        const char *dev = (argc - argi >= 3) ? argv[argi+2] : NULL;
        ip_route_show(dev);
    } else if (strcmp(argv[argi], "addr") == 0 && strcmp(argv[argi+1], "show") == 0) {
        const char *dev = (argc - argi >= 3) ? argv[argi+2] : NULL;
        ip_addr_show(dev);
    } else if ((strcmp(argv[argi], "neigh") == 0 || strcmp(argv[argi], "neighbor") == 0) && strcmp(argv[argi+1], "show") == 0) {
        const char *dev = (argc - argi >= 3) ? argv[argi+2] : NULL;
        ip_neigh_show(dev);
    } else {
        fprintf(stderr, "Invalid command\n");
        return 1;
    }

    return 0;
}
