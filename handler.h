#ifndef HANDLER_H
#define HANDLER_H

#include <unistd.h>

struct nward_hand_args {
	char *name;
	int lhdr_len;
	int maxticks; // max ticks
	useconds_t usec;  // seconds per tick
	int warn;
	int live;
};

void nward_config_incoming (pcap_t *pcap);
void nward_config_both (pcap_t *pcap);

void nward_udp_handler  (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void nward_ack_handler  (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void nward_syn_handler  (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void nward_echo_handler (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
#endif /* HANDLER_H */
