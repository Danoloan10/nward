#include "handler.h"

void nward_echo_handler (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	int port = -1;
	struct nward_hand_args args = *((struct nward_hand_args *) user);
	struct ipv4_head iphead = *((struct ipv4_head *) (bytes + args.lhdr_len));

	if (IPVERSION(&iphead) != 4) {
		print_not_supported(h->ts, IPVERSION(&iphead));
		return;
	}

	if (iphead.proto == 6 || iphead.proto == 17) { //UDP or TCP
		port = ntohs(((u_short *)(bytes + args.lhdr_len + IPV4HDRLEN(&iphead)))[1]);
	}
	char str[128];
	snprintf(str, 128, "%s attack", args.name);
	str[127] = '\0';
	notify_attack(str, h->ts, iphead.saddr, iphead.daddr, port);
}
