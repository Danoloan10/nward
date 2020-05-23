#ifndef SYNNED_H
#define SYNNED_H

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "vector/vector.h"
#include "head/head.h"

#define SYNNED_INITIALIZER { VECTOR_INITIALIZER(sizeof(struct tcp_con)), PTHREAD_MUTEX_INITIALIZER };

struct tcp_con {
	int ip_ver;
	union {
		ipv4_addr ipv4;
		ipv6_addr ipv6;
	} dst_addr;
	union {
		ipv4_addr ipv4;
		ipv6_addr ipv6;
	} src_addr;
	u_short dst_port;
	u_short src_port;
	int replied;
	int finning;
};

struct synned_list {
	vector_t vector;
	pthread_mutex_t lock;
};

int synned_match (struct synned_list *list, const struct tcp_con *pcon, int *pi);
int synned_add (struct synned_list *list, const struct tcp_con *pcon);
void synned_set_replied (struct synned_list *list, int i, int r);
void synned_set_finning (struct synned_list *list, int i, int f);
struct tcp_con synned_get (struct synned_list *list, int i);
void synned_remove (struct synned_list *list, const struct tcp_con *pcon);

#endif
