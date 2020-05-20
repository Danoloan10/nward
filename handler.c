#include "head.h"
#include "handler.h"

#include <stdio.h>

void nward_echo_handler (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	//TODO
	struct nward_hand_args args = *((struct nward_hand_args *) user);
	struct ipv4_head iphead = *((struct ipv4_head *) (bytes + args.lhdr_len));
	printf("packet detected: %s, %d.%d.%d.%d\n", args.name,
			iphead.saddr.bytes[0],
			iphead.saddr.bytes[1],
			iphead.saddr.bytes[2],
			iphead.saddr.bytes[3]);
}

void nward_ack_handler  (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	//TODO
	struct nward_hand_args args = *((struct nward_hand_args *) user);
	struct ipv4_head iphead = *((struct ipv4_head *) (bytes + args.lhdr_len));
	printf("packet detected: %s, %d.%d.%d.%d\n", args.name,
			iphead.saddr.bytes[0],
			iphead.saddr.bytes[1],
			iphead.saddr.bytes[2],
			iphead.saddr.bytes[3]);
}
