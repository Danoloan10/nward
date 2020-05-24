#include "handler.h"

#include "data/synned.h"
#include "data/susp.h"

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
			src_port: src_port,
			replied:  0,
			finning:  0
	};
	if (TCPACK(tcphead.flags)) {
		/* si se recibe un ack, se guarda la conexión a espera de una respuesta */

		// synned_match devuelve 0 si la conexión tcpcon no está en la lista synned,
		// devuelve 1 si hay una entrada de la conexión en la misma dirección,
		// y -1 si hay una entrada de la conexión en la dirección contraria
		int i, ret = synned_match(&synned, &tcpcon, &i);
		if (ret == 0) {
			// primer ack de la conexión
			if (synned_add(&synned, &tcpcon)) {
				fprintf(stderr, "synned_add(): error\n");
				return;
			}
		} else if (ret < 0) {
			// respuesta al primer ack de la conexión
			synned_set_replied(&synned, i, 1);
		}
	} 
	if (TCPRST(tcphead.flags) || TCPFIN(tcphead.flags)) {
		// synned_match devuelve 0 si la conexión tcpcon no está en la lista synned,
		// devuelve 1 si hay una entrada de la conexión en la misma dirección,
		// y -1 si hay una entrada de la conexión en la dirección contraria
		int i, ret = synned_match(&synned, &tcpcon, &i);
		if (ret) {
			struct tcp_con found = synned_get(&synned, i);

			if (TCPRST(tcphead.flags)) {
				if (ret < 0 && !(found.replied)){
					// si el paquete es RST, no se ha respondido con ACK al ACK del primero que se
					// ha leído y el RST viene del receptor de ese primer ACK, se considera al que
					// recibe el RST sospechoso
					if (susp_tick_addr(&susp, tcpcon.dst_addr.ipv4, args.maxticks)) {
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
				}
				if (!(found.finning)) {
					// si no está en la fase FIN, RST fuerza desconexión.
					// si está en la fase FIN, RST puede ser porque la conexión esté
					// medio cerrada
					synned_remove(&synned, &tcpcon);
				}
			} else { /* if (TCPFIN(tcphead.flags)) */
				if (!(found.finning)) {
					// si aún no se está realizando el handshake fin, marcar qué lado
					// de la conexión lo ha empezado
					synned_set_finning(&synned, i, ret > 0 ? 1 : -1);
				} else {
					if ((ret > 0 && found.finning < 0) || (ret < 0 && found.finning > 0)) {
						// eliminar cuando ambas partes hayan enviado FIN
						synned_remove(&synned, &tcpcon);
					}
				}
			}
		}
	}
}
