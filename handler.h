#ifndef HANDLER_H
#define HANDLER_H

struct nward_hand_args {
	char *name;
	int lhdr_len;
};

void nward_ack_handler (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void nward_echo_handler (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
#endif /* HANDLER_H */
