#ifndef SUSP_H
#define SUSP_H

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vector/vector.h"
#include "head/head.h"

#define SUSP_INITIALIZER { VECTOR_INITIALIZER(sizeof(struct suspect)), PTHREAD_MUTEX_INITIALIZER }

struct u_ip_port {
	int t;
	union {
		ipv4_addr ipv4;
		ipv6_addr ipv6;
	} addr;
	u_short port;	
};

struct suspect {
	int ip_ver;
	struct u_ip_port u;
	int ticks;
};

struct susp_list {
	vector_t vector;
	pthread_mutex_t lock;
};

void susp_tick_offline (struct susp_list *list, struct timeval ts, useconds_t usec);
int susp_start_live_ticker (struct susp_list *list, useconds_t usec);
int susp_tick_addr (struct susp_list *list, const ipv4_addr addr, int max);
int susp_tick_port (struct susp_list *list, const u_short port, int max);
int susp_tick_both (struct susp_list *list, const ipv4_addr addr, const u_short port, int max);

#endif
