#include "handler.h"

#include "data/synned.h"
#include "data/susp.h"

void nward_syn_handler  (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	static struct synned_list synned = SYNNED_INITIALIZER;
	static struct susp_list   susp   = SUSP_INITIALIZER;
	static int alrm_started = 0;

	struct nward_hand_args args = *((struct nward_hand_args *) user);
	struct ipv4_head iphead = *((struct ipv4_head *) (bytes + args.lhdr_len));

	if (IPVERSION(&iphead) != 4) {
		print_not_supported(h->ts, IPVERSION(&iphead));
		return;
	}

	// empezar temporizador de lista de sospechosos
	if (args.live) {
		if (!alrm_started) {
			while (susp_start_live_ticker(&susp, args.usec));
			alrm_started = 1;
		}
	} else {
		susp_tick_offline(&susp, h->ts, args.usec);
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
	int i, ret = synned_match(&synned, &tcpcon, &i);
	if (ret == 0) {
		// si no ha sido registrada la conexión asociada al paquete
		if (TCPSYN(tcphead.flags)) {
			// comienza una conexión
			if (synned_add(&synned, &tcpcon)) {
				fprintf(stderr, "synned_add(): error\n");
				return;
			}
		}
	} else if (ret > 0) {
		if (TCPRST(tcphead.flags)) {
			// será SYN si no se completa el saludo triple, 
			// y se responde RST antes que ACK desde la parte que envió el primer SYN
			if (susp_tick_addr(&susp, tcpcon.src_addr.ipv4, args.maxticks)) {
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
			synned_remove(&synned, &tcpcon);
		} else if (TCPACK(tcphead.flags)) {
			synned_remove(&synned, &tcpcon);
		}
	} else if (ret < 0) {
		if (TCPRST(tcphead.flags)) {
			// Un escaneo TCP SYN espera un RST como respuesta
			// al primer SYN si el puerto está cerrado (igual que TCP Connect)
			if (susp_tick_addr(&susp, tcpcon.dst_addr.ipv4, args.maxticks)) {
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
			synned_remove(&synned, &tcpcon);
		}
	}
}
