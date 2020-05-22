#ifndef SYNNED_H
#define SYNNED_H
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

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
	struct tcp_con *synned;
	size_t s_size;
	size_t s_cap;
	pthread_mutex_t lock;
};

static int match_synned (struct synned_list *list, const struct tcp_con *pcon, int *pi)
{
	struct tcp_con con = *pcon;
	struct tcp_con syn;
	int ret = 0;

	pthread_mutex_lock(&list->lock);
	for (int i = 0; i < list->s_size; i++) {
		syn = list->synned[i];
		if (syn.ip_ver == con.ip_ver) {
			if (syn.ip_ver == 4 &&
				syn.dst_port == con.dst_port &&
				syn.src_port == con.src_port &&
				!memcmp(&syn.dst_addr, &con.dst_addr, sizeof(con.dst_addr.ipv4)) &&
				!memcmp(&syn.src_addr, &con.src_addr, sizeof(con.src_addr.ipv4)))
			{
				*pi = i;
				ret = 1;
			} else {
				if (syn.ip_ver == 4 &&
					syn.src_port == con.dst_port &&
					syn.dst_port == con.src_port &&
					!memcmp(&syn.src_addr, &con.dst_addr, sizeof(con.dst_addr.ipv4)) &&
					!memcmp(&syn.dst_addr, &con.src_addr, sizeof(con.src_addr.ipv4)))
				{
					*pi = i;
					ret = -1;
				}
			}
		}
	}
	pthread_mutex_unlock(&list->lock);
	return ret;
}
static int add_synned (struct synned_list *list, const struct tcp_con *pcon)
{
	int ret = 0;
	pthread_mutex_lock(&list->lock);
	if (list->synned == NULL) {
		void *newsyn = calloc(16, sizeof(struct tcp_con));
		if (newsyn == NULL) ret = -1;
		else list->synned = newsyn;
	} else if (list->s_size == list->s_cap) {
		void *newsyn = realloc(list->synned, list->s_cap + list->s_cap);
		if (newsyn == NULL) ret = -1;
		else list->synned = newsyn;
	} 
	if (!ret) {
		list->synned[list->s_size] = *pcon;
		list->s_size++;
	}
	pthread_mutex_unlock(&list->lock);
	return ret;
}

static void remove_synned (struct synned_list *list, const struct tcp_con *pcon) {
	int i, ret = match_synned (list, pcon, &i);
	pthread_mutex_lock(&list->lock);
	if (ret && list->s_size > 0) {
		if (i == 0 && list->s_size == 1) {
			free (list->synned);
			list->synned = NULL;
		} else if (i < list->s_size-1) {
			memmove (list->synned + i, list->synned + i+1, sizeof(*list->synned) * (list->s_size - i)); 
		}
		list->s_size--;
	}
	pthread_mutex_unlock(&list->lock);
}

#endif
