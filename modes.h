#define NW_FILTER_SYN  "tcp[tcpflags] & (tcp-syn | tcp-ack) != 0"
#define NW_FILTER_ACK  "tcp[tcpflags] & (tcp-syn | tcp-ack) != 0"
#define NW_FILTER_XMAS "tcp[tcpflags] & (tcp-fin | tcp-push | tcp-urg) = (tcp-fin | tcp-push | tcp-urg)"
#define NW_FILTER_NULL "tcp[tcpflags] = 0"
#define NW_FILTER_FIN  "tcp[tcpflags] & (tcp-fin) = tcp-fin"

#include "handler.h"

struct mode_opt modes[] = {
    /*opt  name    filter          callback           */
	{ 'S', "syn",  NW_FILTER_SYN,  nward_echo_handler }, //TODO
	{ 'A', "ack",  NW_FILTER_ACK,  nward_ack_handler }, //TODO
	{ 'X', "xmas", NW_FILTER_XMAS, nward_echo_handler },
	{ 'N', "null", NW_FILTER_NULL, nward_echo_handler },
	{ 'F', "fin",  NW_FILTER_FIN,  nward_echo_handler },
};
