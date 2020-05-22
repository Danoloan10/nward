#include "head.h"
#include "handler.h"
#include "synned.h"
#include "susp.h"

#include <stdio.h>
#include <hashset.h>
#include <string.h>
#include <pthread.h>

static inline void print_warn (struct timeval ts) 
{
	printf("( %ld.%04ld ) - warning - ", ts.tv_sec, ts.tv_usec/100);
}

static inline void print_scan (struct timeval ts)
{
	printf("[ %ld.%04ld ] * SCAN * ", ts.tv_sec, ts.tv_usec/100);
}

static inline void print_not_supported (struct timeval ts, int vers)
{
	print_warn(ts);
	printf(" packet not analysed, IP version (%d) not supported\n", vers);
}

static void notify_warning (const char *msg, struct timeval ts, ipv4_addr attacker, ipv4_addr victim, int port) {
	print_warn (ts);
	printf("%s: from %d.%d.%d.%d to %d.%d.%d.%d",
			msg,
			attacker.bytes[0], attacker.bytes[1], attacker.bytes[2], attacker.bytes[3],
			victim.bytes[0],   victim.bytes[1],   victim.bytes[2],   victim.bytes[3]
		  );
	if (port > 0) {
		printf(" (port %d)", port);
	}
	printf("\n");
}

static void notify_attack (const char *msg, struct timeval ts, ipv4_addr attacker, ipv4_addr victim, int port) {
	print_scan (ts);
	printf("%s: from %d.%d.%d.%d to %d.%d.%d.%d",
			msg,
			attacker.bytes[0], attacker.bytes[1], attacker.bytes[2], attacker.bytes[3],
			victim.bytes[0],   victim.bytes[1],   victim.bytes[2],   victim.bytes[3]
		  );
	if (port > 0) {
		printf(" (port %d)", port);
	}
	printf("\n");
}

void nward_config_incoming (pcap_t *pcap) {
	pcap_setdirection(pcap, PCAP_D_IN);
}

void nward_config_both (pcap_t *pcap) {
	pcap_setdirection(pcap, PCAP_D_INOUT);
}

void nward_echo_handler (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	int port = -1;
	struct nward_hand_args args = *((struct nward_hand_args *) user);
	struct ipv4_head iphead = *((struct ipv4_head *) (bytes + args.lhdr_len));

	if (IPVERSION(&iphead) != 4) {
		print_not_supported(h->ts, IPVERSION(&iphead));
		return;
	}

	if (iphead.proto == 6 || iphead.proto == 17) { //UDP or TCP
		port = ntohs(((u_short *)(bytes + args.lhdr_len + IPV4HDRLEN(&iphead)))[1]);
	}
	char str[128];
	snprintf(str, 128, "%s attack", args.name);
	str[127] = '\0';
	notify_attack(str, h->ts, iphead.saddr, iphead.daddr, port);
}

void nward_udp_handler  (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	static struct susp_list susp = { NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER };
	static int alrm_started = 0;

	struct nward_hand_args args = *((struct nward_hand_args *) user);
	struct ipv4_head iphead = *((struct ipv4_head *) (bytes + args.lhdr_len));
	struct udp_head udphead = *((struct udp_head  *) (bytes + args.lhdr_len + IPV4HDRLEN(&iphead)));

	if (IPVERSION(&iphead) != 4) {
		print_not_supported(h->ts, IPVERSION(&iphead));
		return;
	}

	if (args.live) {
		if (!alrm_started) {
			while (start_live_ticker(&susp, args.usec));
			alrm_started = 1;
		}
	} else {
		tick_offline(&susp, h->ts, args.usec);
	}

	u_short dst_port = ntohs(udphead.dport);

	if (tick_susp_tcp(&susp, iphead.daddr, args.maxticks)) {
		notify_attack("UDP scan",
				h->ts,
				iphead.saddr,
				iphead.daddr,
				dst_port);
	} else if (args.warn) {
		notify_warning("UDP incoming packet",
				h->ts,
				iphead.saddr,
				iphead.daddr,
				dst_port);
	}
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
	static struct synned_list synned = { NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER };
	static struct susp_list   susp   = { NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER };
	static int alrm_started = 0;

	struct nward_hand_args args = *((struct nward_hand_args *) user);
	struct ipv4_head iphead = *((struct ipv4_head *) (bytes + args.lhdr_len));

	if (IPVERSION(&iphead) != 4) {
		print_not_supported(h->ts, IPVERSION(&iphead));
		return;
	}

	if (args.live) {
		if (!alrm_started) {
			while (start_live_ticker(&susp, args.usec));
			alrm_started = 1;
		}
	} else {
		tick_offline(&susp, h->ts, args.usec);
	}

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
			finning:  0
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

			if (TCPRST(tcphead.flags)) {
				if (ret < 0 && !(found.replied)){
					if (tick_susp_tcp(&susp, tcpcon.dst_addr.ipv4, args.maxticks)) {
						notify_attack("ACK scan",
								h->ts,
								tcpcon.dst_addr.ipv4,
								tcpcon.src_addr.ipv4,
								tcpcon.src_port);
					} else if (args.warn) {
						notify_warning("ACK scan",
								h->ts,
								tcpcon.dst_addr.ipv4,
								tcpcon.src_addr.ipv4,
								tcpcon.src_port);
					}
					/*
					   if (tick_susp_tcp(&susp, tcpcon.src_addr.ipv4, maxticks))
					   notify_attack("ACK scan", tcpcon.src_addr.ipv4, tcpcon.dst_addr.ipv4, tcpcon.dst_port);
					   */
				}
				if (!(found.finning)) {
					// si no está en la fase FIN, RST fuerza desconexión
					remove_synned(&synned, &tcpcon);
				}
			} else { /* if (TCPFIN(tcphead.flags)) */
				if (!(found.finning)) {
					pthread_mutex_lock(&synned.lock);
					synned.synned[i].finning = ret > 0 ? 1 : -1;
					pthread_mutex_unlock(&synned.lock);
				} else {
					if ((ret > 0 && found.finning < 0) || (ret < 0 && found.finning > 0)) {
						// eliminar cuando ambas partes hayan enviado FIN
						remove_synned(&synned, &tcpcon);
					}
				}
			}
		}
	}
}

void nward_syn_handler  (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	static struct synned_list synned = { NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER };
	static struct susp_list   susp   = { NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER };
	static int alrm_started = 0;

	struct nward_hand_args args = *((struct nward_hand_args *) user);
	struct ipv4_head iphead = *((struct ipv4_head *) (bytes + args.lhdr_len));

	if (IPVERSION(&iphead) != 4) {
		print_not_supported(h->ts, IPVERSION(&iphead));
		return;
	}

	if (args.live) {
		if (!alrm_started) {
			while (start_live_ticker(&susp, args.usec));
			alrm_started = 1;
		}
	} else {
		tick_offline(&susp, h->ts, args.usec);
	}

	struct tcp_head tcphead = *((struct tcp_head *) (bytes + args.lhdr_len + IPV4HDRLEN(&iphead)));
	u_short src_port = ntohs(tcphead.src_port);
	u_short dst_port = ntohs(tcphead.dst_port);
	struct tcp_con tcpcon = (struct tcp_con) {
ip_ver: 4,
			dst_addr: { ipv4: iphead.daddr },
			src_addr: { ipv4: iphead.saddr },
			dst_port: dst_port,
			src_port: src_port
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
			if (tick_susp_tcp(&susp, tcpcon.src_addr.ipv4, args.maxticks)) {
				notify_attack("SYN scan, notified port open",
						h->ts,
						tcpcon.src_addr.ipv4,
						tcpcon.dst_addr.ipv4,
						tcpcon.dst_port);
			} else if (args.warn) {
				notify_warning("SYN scan, notified port open",
						h->ts,
						tcpcon.dst_addr.ipv4,
						tcpcon.src_addr.ipv4,
						tcpcon.src_port);
			}
			remove_synned(&synned, &tcpcon);
		} else if (TCPACK(tcphead.flags)) {
			remove_synned(&synned, &tcpcon);
		}
	} else if (ret < 0) {
		if (TCPRST(tcphead.flags)) {
			if (tick_susp_tcp(&susp, tcpcon.dst_addr.ipv4, args.maxticks)) {
				notify_attack("SYN scan, notified port closed",
						h->ts,
						tcpcon.dst_addr.ipv4,
						tcpcon.src_addr.ipv4,
						tcpcon.src_port);
			} else if (args.warn) {
				notify_warning("SYN scan, notified port closed",
						h->ts,
						tcpcon.dst_addr.ipv4,
						tcpcon.src_addr.ipv4,
						tcpcon.src_port);
			}
			remove_synned(&synned, &tcpcon);
		}
	}
}
