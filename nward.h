#ifndef NWARD_H

#include <pcap/pcap.h>

#define N_MODES (sizeof (modes) / sizeof (struct mode_opt))

struct mode_opt {
	char opt;
	char *name;
	char *filter;
	pcap_handler callback;
};
typedef struct mode_opt *nward_mode_t;

#include "modes.h"

#endif /* NWARD_H */
