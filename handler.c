#include "head.h"
#include "handler.h"

#include <stdio.h>
#include <hashset.h>
#include <string.h>
#include <pthread.h>

void nward_config_incoming (pcap_t *pcap) {
	pcap_setdirection(pcap, PCAP_D_IN);
}

void nward_config_both (pcap_t *pcap) {
	pcap_setdirection(pcap, PCAP_D_INOUT);
}

void nward_echo_handler (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	//TODO
	struct nward_hand_args args = *((struct nward_hand_args *) user);
	struct ipv4_head iphead = *((struct ipv4_head *) (bytes + args.lhdr_len));
	printf("packet detected: %s, %d.%d.%d.%d\n", args.name,
			iphead.saddr.bytes[0],
			iphead.saddr.bytes[1],
			iphead.saddr.bytes[2],
			iphead.saddr.bytes[3]);
}

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
	int finned;
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
	struct tcp_con con = *pcon;
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

/**
 * ACK scan si:
 * 	- se escucha un RST en una conexión TCP para la que la máquina que envía el RST
 * 		no ha enviado ningún ACK.
 * 	- Las conexiones se dan por establecidas cuando se esucha un ACK en ellas.
 * 	- Las conexiones terminan si se escuchan dos FIN seguidos o si se esucucha un RST
 * 	- Algunas implementaciones de TCP pueden esperar FIN después de un RST.
 * 		Este comportamiento se trata como escaneo.
 */
void nward_ack_handler  (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	//TODO

	static struct synned_list synned = { NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER };

	struct nward_hand_args args = *((struct nward_hand_args *) user);
	struct ipv4_head iphead = *((struct ipv4_head *) (bytes + args.lhdr_len));

	if (iphead.proto == 6) {
		struct tcp_head tcphead = *((struct tcp_head *) (bytes + args.lhdr_len + IPV4HDRLEN(&iphead)));
		u_short src_port = ntohs(tcphead.src_port);
		u_short dst_port = ntohs(tcphead.dst_port);
		struct tcp_con tcpcon = (struct tcp_con) {
ip_ver: 4,
			dst_addr: { ipv4: iphead.daddr },
			src_addr: { ipv4: iphead.saddr },
			dst_port: dst_port,
			src_port: src_port,
			replied:  0,
			finned: 0
		};
		if (TCPACK(tcphead.flags)) {
			int i, ret = match_synned(&synned, &tcpcon, &i);
			if (ret == 0) {
				if (add_synned(&synned, &tcpcon)) {
					fprintf(stderr, "add_synned(): error\n");
					return;
				}
			} else if (ret < 0) { // response of recorded ack
				pthread_mutex_lock(&synned.lock);
				synned.synned[i].replied = 1;
				pthread_mutex_unlock(&synned.lock);
			}
		} 
		if (TCPRST(tcphead.flags) || TCPFIN(tcphead.flags)) {
			int i, ret = match_synned(&synned, &tcpcon, &i);
			if (ret) {
				pthread_mutex_lock(&synned.lock);
				struct tcp_con found = synned.synned[i];
				pthread_mutex_unlock(&synned.lock);

				if (ret < 0 && !(found.replied) && TCPRST(tcphead.flags)) {
					printf("ACK scan detected: from %d.%d.%d.%d:%d to %d.%d.%d.%d:%d\n",
							iphead.daddr.bytes[0], iphead.daddr.bytes[1], iphead.daddr.bytes[2], iphead.daddr.bytes[3], dst_port,
							iphead.saddr.bytes[0], iphead.saddr.bytes[1], iphead.saddr.bytes[2], iphead.saddr.bytes[3], src_port
						  );
				}

				// TODO
				// eliminar si:
				// 	- FIN handshake completado
				// 	- FIN, RST, FIN, RST es válido (ver imagen)
				remove_synned(&synned, &tcpcon);
			}
		}
	}
}

void nward_syn_handler  (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	static struct synned_list synned = { NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER };

	struct nward_hand_args args = *((struct nward_hand_args *) user);
	struct ipv4_head iphead = *((struct ipv4_head *) (bytes + args.lhdr_len));

	if (iphead.proto == 6) {
		struct tcp_head tcphead = *((struct tcp_head *) (bytes + args.lhdr_len + IPV4HDRLEN(&iphead)));
		u_short src_port = ntohs(tcphead.src_port);
		u_short dst_port = ntohs(tcphead.dst_port);
		struct tcp_con tcpcon = (struct tcp_con) {
ip_ver: 4,
			dst_addr: { ipv4: iphead.daddr },
			src_addr: { ipv4: iphead.saddr },
			dst_port: dst_port,
			src_port: src_port,
			replied:  0,
			finned: 0
		};
		int i, ret = match_synned(&synned, &tcpcon, &i);
		if (ret == 0) {
			if (TCPSYN(tcphead.flags)) {
				if (add_synned(&synned, &tcpcon)) {
					fprintf(stderr, "add_synned(): error\n");
					return;
				}
			}
		} else if (ret > 0) {
			if (TCPRST(tcphead.flags)) {
				printf("SYN scan detected: from %d.%d.%d.%d:%d to %d.%d.%d.%d:%d\n",
						iphead.daddr.bytes[0], iphead.daddr.bytes[1], iphead.daddr.bytes[2], iphead.daddr.bytes[3], dst_port,
						iphead.saddr.bytes[0], iphead.saddr.bytes[1], iphead.saddr.bytes[2], iphead.saddr.bytes[3], src_port
					  );
				printf("\t|=> Notified: port open\n");
				remove_synned(&synned, &tcpcon);
			} else if (TCPACK(tcphead.flags)) {
				remove_synned(&synned, &tcpcon);
			}
		} else if (ret < 0) {
			if (TCPRST(tcphead.flags)) {
				printf("SYN scan detected: from %d.%d.%d.%d:%d to %d.%d.%d.%d:%d;\n",
						iphead.daddr.bytes[0], iphead.daddr.bytes[1], iphead.daddr.bytes[2], iphead.daddr.bytes[3], dst_port,
						iphead.saddr.bytes[0], iphead.saddr.bytes[1], iphead.saddr.bytes[2], iphead.saddr.bytes[3], src_port
					  );
				printf("\t|=> Notified: port closed\n");
				remove_synned(&synned, &tcpcon);
			}
		}
	}
}
