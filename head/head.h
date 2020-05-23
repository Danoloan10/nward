#ifndef HEADS_H
#define HEADS_H

#include <pcap/pcap.h>

#include "ipv4_head.h"

#define IPVERSION(__ptr) ((*((u_char *)__ptr) >> 4) & 0x0F)
#define IPV4HDRLEN(__ptr) ((int) (*((u_char *)__ptr) & (u_char) 0x0F) * 4)

#define TCPSYN(__flags) ((u_char) __flags & (u_char) 0x02)
#define TCPACK(__flags) ((u_char) __flags & (u_char) 0x10)
#define TCPRST(__flags) ((u_char) __flags & (u_char) 0x04)
#define TCPFIN(__flags) ((u_char) __flags & (u_char) 0x01)

/* NOTE: uses u_* (pcap.h) instead of u*_t (stdint.h) */

typedef struct ipv6_addr {
	u_char bytes[8];
} ipv6_addr;

/* IPv6 header */
struct ipv6_head {
    u_char  ver_tc1;   // Version (4 bits) + Traffic Class (first 4 bits)
    u_char  tc2_fl1;   // Traffic Class (last 4 bits) + Flow Label (first 4 bits)
    u_short fl2;       // Flow Label (last 16 bits)
    u_short pl_len;    // Payload length
    u_char  next_head; // Next Header
    u_char  hop_limit; // Hop Limit
    ipv6_addr saddr;   // Source address
    ipv6_addr daddr;   // Destination address
};

/* IPv6 hop by hop extension header (incomplete) */
struct ipv6_head_hbh {
	u_char next_head;
	u_char head_len;
};

/* IPv6 routing (incomplete) */
struct ipv6_head_rout {
	u_char next_head;
	u_char head_len;
};

/* IPv6 fragment */
struct ipv6_head_frag {
	u_char bytes[8];
};

/* TCP header */
struct tcp_head {
	u_short src_port;
	u_short dst_port;
	u_int seqno;
	u_int ackno;
	u_char doff_ns;
	u_char flags;
	u_short win_size;
	u_short checksum;
	u_short urg_ptr;
	u_char opts_pad[40];
};

#endif /* HEADS_H */
