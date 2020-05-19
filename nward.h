#ifndef NWARD_H

#include <pcap/pcap.h>

#define N_MODES (sizeof (modes) / sizeof (struct mode_opt))

void nward_mode_xmas (pcap_t *pcap, int pc);
void nward_echo_handler (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

struct mode_opt {
	char opt;
	char *name;
	char *filter;
	pcap_handler callback;
};
typedef struct mode_opt *nward_mode_t;

#define NW_FILTER_XMAS "tcp[tcpflags] & (tcp-fin | tcp-push | tcp-urg) = (tcp-fin | tcp-push | tcp-urg)"

#include "modes.h"

#endif /* NWARD_H */
