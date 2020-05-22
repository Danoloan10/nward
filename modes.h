#define NW_FILTER_UDP  "udp"
#define NW_FILTER_SYN  "tcp and tcp[tcpflags] & (tcp-syn | tcp-ack | tcp-rst) != 0"
#define NW_FILTER_ACK  "tcp and tcp[tcpflags] & (tcp-ack | tcp-rst) != 0"
#define NW_FILTER_XMAS "tcp and tcp[tcpflags] & (tcp-fin | tcp-push | tcp-urg) = (tcp-fin | tcp-push | tcp-urg)"
#define NW_FILTER_NULL "tcp and tcp[tcpflags] = 0"
#define NW_FILTER_FIN  "tcp and tcp[tcpflags] = tcp-fin"

#include "handler.h"

struct mode_opt modes[] = {
    /*opt  name    filter          config                 callback           */
	{ 'U', "udp",  NW_FILTER_UDP,  nward_config_incoming, nward_udp_handler  },
	{ 'S', "syn",  NW_FILTER_SYN,  nward_config_both,     nward_syn_handler  },
	{ 'A', "ack",  NW_FILTER_ACK,  nward_config_both,     nward_ack_handler  }, //TODO revisar finalizacion de conexion
	{ 'X', "xmas", NW_FILTER_XMAS, nward_config_incoming, nward_echo_handler },
	{ 'N', "null", NW_FILTER_NULL, nward_config_incoming, nward_echo_handler },
	{ 'F', "fin",  NW_FILTER_FIN,  nward_config_incoming, nward_echo_handler },
};
