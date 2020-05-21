#ifndef NWARD_H

#include <pcap/pcap.h>

#define N_MODES (sizeof (modes) / sizeof (struct mode_opt))

struct mode_opt {
	char opt;
	char *name;
	char *filter;
	void (*config)(pcap_t*);
	pcap_handler callback;
};
typedef struct mode_opt *nward_mode_t;

static inline int ltype_to_lhdrlen (int linktype) {
	int linkhdrlen;
	switch (linktype)
	{
		case DLT_NULL:
			linkhdrlen = 4;
			break;

		case DLT_EN10MB:
			linkhdrlen = 14;
			break;
		case DLT_LINUX_SLL:
			linkhdrlen = 16;
			break;
		case DLT_SLIP:
		case DLT_PPP:
			linkhdrlen = 24;
			break;
		default:
			linkhdrlen = -1;
	}
	return linkhdrlen;
}

#include "modes.h"

#endif /* NWARD_H */
