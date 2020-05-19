#include <pcap/pcap.h>
#include <stddef.h>
#include <stdio.h>

#define NWARD_FILTER_XMAS "tcp[tcpflags] & (tcp-fin | tcp-push | tcp-urg) = (tcp-fin | tcp-push | tcp-urg)"

static void list_devs () {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *list;
	if (!pcap_findalldevs(&list, errbuf)) {
		while (list != NULL && list->next != NULL) {
			printf("%s, ", list->name);
			list = list->next;
		}
		if (list != NULL) {
			printf("%s\n", list->name);
		}
	} else {
		fprintf(stderr, "%s\n", errbuf);
	}
}

void nward_handler (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
	// TODO
	printf("pakcet detected: %s\n", user);
}

// options:
// -D dev
// -sX Xmas
// -c count
// -s "filter"
int main(int argc, char **argv) {
	pcap_t *pcap;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	int err;
	
	//TODO list devs

	pcap = pcap_open_live(NULL, BUFSIZ, 0, -1, errbuf);

	if (pcap != NULL) {
		//filter
		struct bpf_program fp;
		pcap_compile(pcap, &fp, NWARD_FILTER_XMAS, 1, PCAP_NETMASK_UNKNOWN); //TODO error
		pcap_setfilter(pcap, &fp); // TODO error
		//setup
		//loop
		pcap_loop(pcap, 0, nward_handler, "xmas"); // TODO error
		err = 0;
	} else {
		err = 1;
		fprintf(stderr, "%s\n", errbuf);
	}

	return err;
}
