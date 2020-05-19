#include <pcap/pcap.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define NW_FILTER_XMAS "tcp[tcpflags] & (tcp-fin | tcp-push | tcp-urg) = (tcp-fin | tcp-push | tcp-urg)"
#define NW_FILTER_XMAS "tcp[tcpflags] & (tcp-fin | tcp-push | tcp-urg) = (tcp-fin | tcp-push | tcp-urg)"

#define NW_SNAPLEN 256

#define NW_SYN  0
#define NW_CONN 1
#define NW_UDP  2
#define NW_FIN  3
#define NW_NULL 4
#define NW_XMAS 5
#define NW_IDLE 6
#define NW_CUST 7

#define NW_MAX_MODES 8

void nward_echo_handler (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
	// TODO
	printf("pakcet detected: %s\n", user);
}

void run_xmas(pcap_t *pcap, int pc) {
	struct bpf_program fp;
	pcap_compile(pcap, &fp, NW_FILTER_XMAS, 1, PCAP_NETMAS_UNKNOWN); //TODO error
	pcap_setfilter(pcap, &fp); // TODO error
	pcap_loop(pcap, pc, nward_echo_handler, "xmas"); // TODO error
	pcap_freecode(&fp);
}

static pcap_t *init_pcap(char *devname) {
	int warn;
	pcap_t *pcap = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_if_t *dev = NULL, *list, *it;
	if (!pcap_findalldevs(&list, errbuf)) {
		it = list;

		if (it == NULL) {
			if (devname == NULL)
				fprintf(stderr, "no devices found%s\n");
			else
				fprintf(stderr, "device %s not found\n", devname);
		} else while (it != NULL && dev == NULL) {
			if (!strcmp(devname, it->name))
				dev = it;
			it = it->next;
		}

		pcap = pcap_create(devname, errbuf);

		if (pcap != NULL) {
			pcap_set_buffer_size(pcap, BUFSIZ);
			pcap_set_snaplen(pcap, NW_SNAPLEN);
			pcap_set_timeout(pcap, 1);

			switch (warn = pcap_activate(pcap)) {
				case 0: //OK
					break;
				//TODO añadir otros warns
				default:
					// activate faiu
					pcap_perror(pcap, "");
			}
		} else {
			// create fail
			fprintf(stderr, "%s\n", errbuf);
		}
	} else {
		// findalldevs fail
		fprintf(stderr, "%s\n", errbuf);
	}


	if (list != NULL) pcap_freealldevs(list);

	return pcap;
}

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
		pcap_freealldevs(list);
	} else {
		fprintf(stderr, "%s\n", errbuf);
	}
}

static void print_usage() {
	fprintf(stderr, "usage"); //TODO
}

// options:
// -D dev
// -sX Xmas
// -c count
// -s "filter"
int main(int argc, char **argv) {
	int err = 0, pc = 0, opt;
	char *dev;

	int modes[NW_MAX_MODES] = { 0, 0, 0, 0, 0, 0, 0 };
	
	pcap_t *pcap;
	
	while ((opt = getopt(argc, argv, "ls:"))) {
		switch (opt) {
			case 's':
				if (optarg[0] == 'X') modes[NW_XMAS] = 1;
				break;
			case 'l':
				list_devs();
				exit(0);
				break;
			case '?':
				print_usage();
				exit(1);
				break;
		}
	}

	pcap = init_pcap();
	if (pcap != NULL) {
		if (modes[NW_XMAS]) run_xmas(pcap, pc, netmask);
		err = 0;
	} else {
		fprintf(stderr, "%s\n", errbuf);
		err = 1;
	}

	return err;
}
