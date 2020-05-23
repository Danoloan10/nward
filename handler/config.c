#include "handler.h"

void nward_config_incoming (pcap_t *pcap) {
	pcap_setdirection(pcap, PCAP_D_IN);
}

void nward_config_both (pcap_t *pcap) {
	pcap_setdirection(pcap, PCAP_D_INOUT);
}
