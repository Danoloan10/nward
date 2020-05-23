#ifndef SUSP_H
#define SUSP_H

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vector/vector.h"
#include "head/head.h"

#define SUSP_INITIALIZER { VECTOR_INITIALIZER(sizeof(struct suspect)), PTHREAD_MUTEX_INITIALIZER }

struct suspect {
	int ip_ver;
	union {
		ipv4_addr ipv4;
		ipv6_addr ipv6;
	} addr;
	int ticks;
};

struct susp_list {
	vector_t vector;
	pthread_mutex_t lock;
};

int susp_add (struct susp_list *list, const struct suspect *psus);
int susp_match (struct susp_list *list, const ipv4_addr addr, int *pi);
void susp_remove (struct susp_list *list, const ipv4_addr addr);
void susp_tick_offline (struct susp_list *list, struct timeval ts, useconds_t usec);
int susp_start_live_ticker (struct susp_list *list, useconds_t usec);
int susp_tick (struct susp_list *list, const ipv4_addr addr, int max);

#endif
