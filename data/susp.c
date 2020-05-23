#include "susp.h"

#include "head/head.h"

int susp_add (struct susp_list *list, const struct suspect *psus)
{
	int ret = 0;
	pthread_mutex_lock(&list->lock);
	struct suspect sus = *psus;
	ret = vector_push_back(&list->vector, &sus);
	pthread_mutex_unlock(&list->lock);
	return ret;
}

int match_susp (struct susp_list *list, const ipv4_addr addr, int *pi)
{
	const struct suspect *sus;
	int ret = 0;

	pthread_mutex_lock(&list->lock);
	for (int i = 0; i < list->vector.size; i++) {
		sus = ((struct suspect *) vector_const_get(&list->vector, i));
		if(sus->ip_ver == 4 && !memcmp(&addr, &sus->addr, sizeof(sus->addr.ipv4)))
		{
			*pi = i;
			ret = 1;
		}
	}
	pthread_mutex_unlock(&list->lock);
	return ret;
}

void remove_susp (struct susp_list *list, const ipv4_addr addr)
{
	int i, ret = match_susp (list, addr, &i);
	pthread_mutex_lock(&list->lock);
	if (ret) {
		vector_erase (&list->vector, i);
	}
	pthread_mutex_unlock(&list->lock);
}

struct args {
	struct susp_list *list;
	useconds_t usec;
};

static void tick_all (struct susp_list *list) {
	pthread_mutex_lock(&list->lock);
	struct suspect *sus;
	for (int i = 0; i < list->vector.size; i++) {
		sus = (struct suspect *) vector_get(&list->vector, i);
		if (sus->ticks > 0) {
			sus->ticks--;
			/*
			printf("%d.%d.%d.%d: s-valor %d (-1)\n",
					list->list[i].addr.ipv4.bytes[0],
					list->list[i].addr.ipv4.bytes[1],
					list->list[i].addr.ipv4.bytes[2],
					list->list[i].addr.ipv4.bytes[3],
					list->list[i].ticks);
			*/
		}
		if (sus->ticks == 0) {
			vector_erase (&list->vector, i);
			i--;
		}
	}
	pthread_mutex_unlock(&list->lock);
}

static void *tick_alrm_hand (void *pargs) {
	struct args args = *((struct args *)pargs);
	free(pargs);
	while (1) {
		struct susp_list *list = args.list;
		tick_all(list);
		usleep(args.usec);
	}
	return NULL;
}

void tick_offline (struct susp_list *list, struct timeval ts, useconds_t usec)
{
	static struct timeval last = { 0, 0 };
	if ((ts.tv_sec - last.tv_sec)*1000000 + (ts.tv_usec - last.tv_usec) > usec) {
		last = ts;
		tick_all(list);
	}
}

int start_live_ticker (struct susp_list *list, useconds_t usec)
{
	struct args *args = malloc(sizeof(struct args));
	if (args != NULL) {
		(*args) = (struct args) { list, usec };
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
		susp_add (list, &sus);
	} else {
		pthread_mutex_lock(&list->lock);
		struct suspect *match = vector_get(&list->vector, i);
		match->ticks++;
		if (match->ticks > max) {
			match->ticks--;
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


