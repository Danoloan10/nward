#include <pcap/pcap.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define NW_SNAPLEN 256

#include "nward.h"

void nward_echo_handler (u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	// TODO
	printf("pakcet detected: %s\n", user);
}

static void run_mode(pcap_t *pcap, int pc, struct mode_opt *mode)
{
	struct bpf_program fp;
	pcap_compile(pcap, &fp, mode->filter, 1, PCAP_NETMASK_UNKNOWN); //TODO error
	pcap_setfilter(pcap, &fp); // TODO error
	pcap_loop(pcap, pc, mode->callback, mode->name); // TODO error
	pcap_freecode(&fp);
}

static pcap_t *init_pcap(char *devname)
{
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
			if (devname == NULL || !strcmp(devname, it->name))
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

static void list_devs ()
{
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

static void print_usage()
{
	fprintf(stderr, "usage"); //TODO
}

// options:
// -D dev
// -sX Xmas
// -c count
// -s "filter"
int main(int argc, char **argv)
{
	int err = 0, pc = 0, opt;
	char *devname = NULL;

	pcap_t *pcap;
	nward_mode_t mode = NULL;

	char optstr[N_MODES+2] = { 0 };
	for (int i = 0; i < N_MODES; i++) {
		optstr[i] = modes[i].opt;
	}
	optstr[N_MODES] = 'l';
	
	while (mode == NULL && (opt = getopt(argc, argv, optstr)) >= 0) {
		for (int i = 0; i < N_MODES; i++) {
			if (modes[i].opt == opt) {
				mode = &modes[i];
			}
		}
		if (mode == NULL) {
			switch (opt) {
				case 'l':
					list_devs();
					exit(0);
					break;
				default:
					print_usage();
					exit(1);
					break;
			}
		}
	}

	if (mode != NULL) {
		pcap = init_pcap(devname);
		if (pcap != NULL) {
			run_mode(pcap, pc, mode);
			err = 0;
		} else {
			err = 1;
		}
	} else {
		print_usage();
	}

	return err;
}
