#include "susp.h"

#include "head/head.h"

static int susp_add (struct susp_list *list, const struct suspect *psus)
{
	int ret = 0;
	struct suspect sus = *psus;
	ret = vector_push_back(&list->vector, &sus);
	return ret;
}

static int susp_match (struct susp_list *list, struct u_ip_port u, int *pi)
{
	const struct suspect *sus;
	int ret = 0;

	for (int i = 0; i < list->vector.size && !ret; i++) {
		sus = ((struct suspect *) vector_const_get(&list->vector, i));
		int ip_match = sus->ip_ver == 4 && !memcmp(&u.addr, &sus->u.addr, sizeof(sus->u.addr.ipv4)) ? 1 : 0;
		int port_match = u.port == sus->u.port ? 1 : 0;
		switch(sus->u.t) {
			case 1:
				ret = ip_match;
				break;
			case 2:
				ret = port_match;
				break;
			case 3:
				ret = port_match & ip_match;
				break;
			default:
				ret = 0;
		}
		if (ret) {
			*pi = i;
		}
	}
	return ret;
}

struct args {
	struct susp_list *list;
	useconds_t usec;
};

static void _tick_all (struct susp_list *list) {
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

static void *_tick_alrm_hand (void *pargs) {
	struct args args = *((struct args *)pargs);
	free(pargs);
	while (1) {
		struct susp_list *list = args.list;
		_tick_all(list);
		usleep(args.usec);
	}
	return NULL;
}

void susp_tick_offline (struct susp_list *list, struct timeval ts, useconds_t usec)
{
	static struct timeval last = { 0, 0 };
	if ((ts.tv_sec - last.tv_sec)*1000000 + (ts.tv_usec - last.tv_usec) > usec) {
		last = ts;
		_tick_all(list);
	}
}

int susp_start_live_ticker (struct susp_list *list, useconds_t usec)
{
	struct args *args = malloc(sizeof(struct args));
	if (args != NULL) {
		(*args) = (struct args) { list, usec };
		pthread_t th;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pthread_create(&th, &attr, _tick_alrm_hand, args);
		return 0;
	} else {
		perror("malloc");
		return 1;
	}
}

static int susp_tick (struct susp_list *list, struct u_ip_port u, int max)
{
	struct suspect sus = {
		ip_ver: 4,
		u:      u,
		ticks:  0
	};
	pthread_mutex_lock(&list->lock);
	int i, danger = 0, ret = susp_match(list, u, &i);
	if (!ret) {
		susp_add (list, &sus);
	} else {
		struct suspect *match = vector_get(&list->vector, i);
		match->ticks++;
		if (match->ticks >= max) {
			if (match->ticks > max)
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
	}		
	pthread_mutex_unlock(&list->lock);
	return danger;
}

int susp_tick_addr (struct susp_list *list, const ipv4_addr addr, int max)
{
	struct u_ip_port u = { t: 0x1, addr: { ipv4: addr } };
	return susp_tick (list, u, max);
}
int susp_tick_port (struct susp_list *list, const u_short port, int max)
{
	struct u_ip_port u = { t: 0x2, port: port };
	return susp_tick (list, u, max);
}
int susp_tick_both (struct susp_list *list, const ipv4_addr addr, const u_short port, int max)
{
	struct u_ip_port u = { t: 0x3, addr: { ipv4: addr }, port: port };
	return susp_tick (list, u, max);
}
