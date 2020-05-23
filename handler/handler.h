#ifndef HANDLER_H
#define HANDLER_H

#include <unistd.h>
#include <pcap/pcap.h>

#include "head/head.h"

struct nward_hand_args {
	char *name;
	int lhdr_len;
	int maxticks; // max ticks
	useconds_t usec;  // seconds per tick
	int warn;
	int live;
};

void print_warn (struct timeval ts);
void print_scan (struct timeval ts);
void print_not_supported (struct timeval ts, int vers);
void notify_warning (const char *msg, struct timeval ts, ipv4_addr attacker, ipv4_addr victim, int port);
void notify_attack (const char *msg, struct timeval ts, ipv4_addr attacker, ipv4_addr victim, int port);

void nward_config_incoming (pcap_t *pcap);
void nward_config_both (pcap_t *pcap);

void nward_echo_handler (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);


void nward_udp_handler  (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void nward_ack_handler  (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void nward_syn_handler  (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void nward_echo_handler (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

#endif /* HANDLER_H */
