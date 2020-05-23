#include "synned.h"

#include "head/head.h"

static int _match_con (const struct tcp_con *con1, const struct tcp_con *con2)
{
	int ret = 0;
	if (con1->ip_ver == con2->ip_ver) {
		if (con1->ip_ver == 4 &&
				con1->dst_port == con2->dst_port &&
				con1->src_port == con2->src_port &&
				!memcmp(&con1->dst_addr, &con2->dst_addr, sizeof(con2->dst_addr.ipv4)) &&
				!memcmp(&con1->src_addr, &con2->src_addr, sizeof(con2->src_addr.ipv4)))
		{
			ret = 1;
		} else {
			if (con1->ip_ver == 4 &&
					con1->src_port == con2->dst_port &&
					con1->dst_port == con2->src_port &&
					!memcmp(&con1->src_addr, &con2->dst_addr, sizeof(con2->dst_addr.ipv4)) &&
					!memcmp(&con1->dst_addr, &con2->src_addr, sizeof(con2->src_addr.ipv4)))
			{
				ret = -1;
			}
		}
	}
	return ret;
}

int synned_match (struct synned_list *list, const struct tcp_con *con, int *pi)
{
	const struct tcp_con *syn;
	int ret = 0;

	pthread_mutex_lock(&list->lock);
	for (int i = 0; i < list->vector.size && !ret; i++) {
		syn = ((struct tcp_con *) vector_const_get(&list->vector, i));
		if ((ret = _match_con (syn, con))) {
			*pi = i;
		}
	}
	pthread_mutex_unlock(&list->lock);
	return ret;
}

int synned_add (struct synned_list *list, const struct tcp_con *pcon)
{
	int ret = 0;
	struct tcp_con con = *pcon;
	pthread_mutex_lock(&list->lock);
	ret = vector_push_back(&list->vector, &con);
	pthread_mutex_unlock(&list->lock);
	return ret;
}

void synned_set_replied (struct synned_list *list, int i, int r)
{
	pthread_mutex_lock(&list->lock);
	struct tcp_con *syn = ((struct tcp_con *) vector_get(&list->vector, i));
	syn->replied = r;
	pthread_mutex_unlock(&list->lock);
}

void synned_set_finning (struct synned_list *list, int i, int f)
{
	pthread_mutex_lock(&list->lock);
	struct tcp_con *syn = ((struct tcp_con *) vector_get(&list->vector, i));
	syn->finning = f;
	pthread_mutex_unlock(&list->lock);
}

struct tcp_con synned_get (struct synned_list *list, int i)
{
	pthread_mutex_lock(&list->lock);
	struct tcp_con con = *((struct tcp_con *) vector_const_get(&list->vector, i));
	pthread_mutex_unlock(&list->lock);
	return con;
}

void synned_remove (struct synned_list *list, const struct tcp_con *pcon)
{
	int i, ret = synned_match (list, pcon, &i);
	pthread_mutex_lock(&list->lock);
	if (ret){
		vector_erase(&list->vector, i);
	}
	pthread_mutex_unlock(&list->lock);
}


