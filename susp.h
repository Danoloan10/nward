#ifndef SUSP_H
#define SUSP_H

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct suspect {
	int ip_ver;
	union {
		ipv4_addr ipv4;
		ipv6_addr ipv6;
	} addr;
	int ticks;
};

struct susp_list {
	struct suspect *list;
	size_t size;
	size_t cap;
	pthread_mutex_t lock;
};

static int add_susp (struct susp_list *list, const struct suspect *psus)
{
	int ret = 0;
	pthread_mutex_lock(&list->lock);
	if (list->list == NULL) {
		void *newsus = calloc(16, sizeof(struct suspect));
		if (newsus == NULL) ret = -1;
		else list->list = newsus;
	} else if (list->size == list->cap) {
		void *newsus = realloc(list->list, list->cap + list->cap);
		if (newsus == NULL) ret = -1;
		else list->list = newsus;
	} 
	if (!ret) {
		list->list[list->size] = *psus;
		list->size++;
	}
	pthread_mutex_unlock(&list->lock);
	return ret;
}

static int match_susp (struct susp_list *list, const ipv4_addr addr, int *pi)
{
	struct suspect sus;
	int ret = 0;

	pthread_mutex_lock(&list->lock);
	for (int i = 0; i < list->size; i++) {
		sus = list->list[i];
		if(sus.ip_ver == 4 &&
		   !memcmp(&addr, &sus.addr, sizeof(sus.addr.ipv4)))
		{
			*pi = i;
			ret = 1;
		}
	}
	pthread_mutex_unlock(&list->lock);
	return ret;
}

static void remove_susp (struct susp_list *list, const ipv4_addr addr) {
	int i, ret = match_susp (list, addr, &i);
	pthread_mutex_lock(&list->lock);
	if (ret && list->size > 0) {
		if (i == 0 && list->size == 1) {
			free (list->list);
			list->list = NULL;
		} else if (i < list->size-1) {
			memmove (list->list + i, list->list + i+1, sizeof(*list->list) * (list->size - i)); 
		}
		list->size--;
	}
	pthread_mutex_unlock(&list->lock);
}

struct args {
	struct susp_list *list;
	int seconds;
};

void *tick_alrm_hand (void *pargs) {
	struct args args = *((struct args *)pargs);
	free(pargs);
	while (1) {
		struct susp_list *list = args.list;
		pthread_mutex_lock(&list->lock);
		for (int i = 0; i < list->size; i++) {
			if (list->list[i].ticks > 0) {
				list->list[i].ticks--;
				/*
				printf("%d.%d.%d.%d: s-valor %d (-1)\n",
						list->list[i].addr.ipv4.bytes[0],
						list->list[i].addr.ipv4.bytes[1],
						list->list[i].addr.ipv4.bytes[2],
						list->list[i].addr.ipv4.bytes[3],
						list->list[i].ticks);
				*/
			}
			if (list->list[i].ticks == 0) {
				pthread_mutex_unlock(&list->lock);
				remove_susp (list, list->list[i].addr.ipv4);
				pthread_mutex_lock(&list->lock);
			}
		}
		pthread_mutex_unlock(&list->lock);
		sleep(args.seconds);
	}
	return NULL;
}

int start_tick_alrm (struct susp_list *list, int seconds) {
	struct args *args = malloc(sizeof(struct args));
	if (args != NULL) {
		(*args) = (struct args) { list, seconds };
		pthread_t th;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pthread_create(&th, &attr, tick_alrm_hand, args);
		return 0;
	} else {
		perror("malloc");
		return 1;
	}
}

int tick_susp_tcp (struct susp_list *list, const ipv4_addr addr, int max)
{
	struct suspect sus = {
		ip_ver: 4,
		addr:   { ipv4: addr },
		ticks:  0
	};
	int i, danger = 0, ret = match_susp(list, addr, &i);
	if (!ret) {
		add_susp (list, &sus);
	} else {
		pthread_mutex_lock(&list->lock);
		list->list[i].ticks++;
		if (list->list[i].ticks > max) {
			list->list[i].ticks--;
			danger = 1;
		} else {
			/*
			printf("%d.%d.%d.%d: s-valor %d (+1)\n",
					addr.bytes[0],
					addr.bytes[1],
					addr.bytes[2],
					addr.bytes[3],
					list->list[i].ticks);
			*/
		}
		pthread_mutex_unlock(&list->lock);
	}		
	return danger;
}

#endif
