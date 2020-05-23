#include "handler.h"

#include "data/susp.h"

void nward_udp_handler  (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	static struct susp_list susp = SUSP_INITIALIZER;
	static int alrm_started = 0;

	struct nward_hand_args args = *((struct nward_hand_args *) user);
	struct ipv4_head iphead = *((struct ipv4_head *) (bytes + args.lhdr_len));
	struct udp_head udphead = *((struct udp_head  *) (bytes + args.lhdr_len + IPV4HDRLEN(&iphead)));

	if (IPVERSION(&iphead) != 4) {
		print_not_supported(h->ts, IPVERSION(&iphead));
		return;
	}

	if (args.live) {
		if (!alrm_started) {
			while (start_live_ticker(&susp, args.usec));
			alrm_started = 1;
		}
	} else {
		tick_offline(&susp, h->ts, args.usec);
	}

	u_short dst_port = ntohs(udphead.dport);

	if (tick_susp_tcp(&susp, iphead.daddr, args.maxticks)) {
		notify_attack("UDP scan",
				h->ts,
				iphead.saddr,
				iphead.daddr,
				dst_port);
	} else if (args.warn) {
		notify_warning("UDP incoming packet",
				h->ts,
				iphead.saddr,
				iphead.daddr,
				dst_port);
	}
}
