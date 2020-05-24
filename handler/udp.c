#include "handler.h"

#include "data/susp.h"

void nward_udp_handler  (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	static struct susp_list conn = SUSP_INITIALIZER; // remember "connections"
	static struct susp_list susp = SUSP_INITIALIZER; // suspects
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
			while (susp_start_live_ticker(&conn, 2*args.usec));
			while (susp_start_live_ticker(&susp, args.usec));
			alrm_started = 1;
		}
	} else {
		susp_tick_offline(&conn, h->ts, 2*args.usec);
		susp_tick_offline(&susp, h->ts, args.usec);
	}

	u_short dst_port = ntohs(udphead.dport);

	if (!susp_tick_both(&conn, iphead.saddr, dst_port, args.maxticks/2)) {
		if (susp_tick_addr(&susp, iphead.saddr, args.maxticks)) {
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
}
