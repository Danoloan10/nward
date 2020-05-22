#include <pcap/pcap.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define NW_SNAPLEN 256

#include "nward.h"

static void run_mode(pcap_t *pcap, int pc, int mt, useconds_t to, int warn, int live, struct mode_opt *mode)
{
	struct bpf_program fp;
	if (pcap_compile(pcap, &fp, mode->filter, 1, PCAP_NETMASK_UNKNOWN)) {
		pcap_perror(pcap, "compile");
	} else {
		int linktype, linkhdrlen;
		if ((linktype = pcap_datalink(pcap)) < 0)
		{
			pcap_perror(pcap, "run_mode");
		} else {
			// TODO semánticamente aquí no
			if ((linkhdrlen = ltype_to_lhdrlen(linktype)) < 0)
				fprintf(stderr, "Unsupported datalink (%d)\n", linktype);
			else
			if (pcap_setfilter(pcap, &fp))
				pcap_perror(pcap, "compile");
			else {
				struct nward_hand_args args = { mode->name, linkhdrlen, mt, to, warn, live };
				if (pcap_loop(pcap, pc, mode->callback, (u_char *) &args)) // TODO sólo devuelve 0 si no hay break
					pcap_perror(pcap, "compile");
			}
		}
		//pcap_freecode(&fp);
	}
}

static pcap_t *init_pcap_file(char *filename, struct mode_opt *mode)
{
	pcap_t *pcap = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap = pcap_open_offline(filename, errbuf);

	if (pcap == NULL) {
		// create fail
		fprintf(stderr, "%s\n", errbuf);
	}

	return pcap;
}

static pcap_t *init_pcap_live(char *devname, struct mode_opt *mode)
{
	int warn;
	pcap_t *pcap = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_if_t *dev = NULL, *list, *it;
	if (!pcap_findalldevs(&list, errbuf)) {
		it = list;

		if (it == NULL) {
			if (devname == NULL)
				fprintf(stderr, "no devices found\n");
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

			// mode config
			mode->config(pcap);

			switch (warn = pcap_activate(pcap)) {
				case 0: //OK
					break;
					//TODO añadir otros warns
				default:
					// activate faiu
					pcap_perror(pcap, "init_pcap");
					pcap_close(pcap);
					pcap = NULL;
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
	fprintf(stderr, "\
Usage:\n\
	nward [options] -type\n\
\n\
All options and arguments following the type argument are ignored\n\
\n\
options:\n\
	-c N - analyse up to N packets (0 or less for infinity, default: 0)\n\
	-d «device»\n\
	       perform live session capturing traffic from «device».\n\
	       If not provided, chooses the first found. Incompatible with -f\n\
	-f «file»\n\
	       perform offline session reading the PCAP file «file». Incompatible with -d\n\
	-l   - list devices available for live session and exit (discards all other options)\n\
	-m M - tolerate up to M suspicious events (must be non-negative, default 10)\n\
	-t T - a tick will last T milliseconds. Each tick a suspicious event is forgotten\n\
	       for every source IP address. In offline sessions, ticks are triggered by\n\
	       the packet reads and timeouts are based on the timestamps of the packets\n\
	       (must be positive, default 100)\n\
	-w   - print scan warnings when suspicious\n\
types:\n\
	-A - ward from ACK scans\n\
	-F - ward from FIN scans\n\
	-N - ward from NULL scans\n\
	-S - ward from SYN scans\n\
	-U - ward from UDP scans\n\
	-X - ward from Xmas scans\n\
Example:\n\
	nward -f file.pcap -c 10 -m 10 -t 2000 -F\n\
");
}

// options:
// -D dev
// -sX Xmas
// -c count
// -s "filter"
int main(int argc, char **argv)
{
	useconds_t to = 100000;
	int err = 0, pc = 0, mt = 10, file = 0, warn = 0, opt;
	char *devname = NULL;

	pcap_t *pcap;
	nward_mode_t mode = NULL;

	char optstr[N_MODES+13] = "ld:m:c:t:f:w";
	for (int i = 0; i < N_MODES; i++) {
		optstr[i+12] = modes[i].opt;
	}

	while (mode == NULL && (opt = getopt(argc, argv, optstr)) >= 0) {
		for (int i = 0; i < N_MODES; i++) {
			if (modes[i].opt == opt) {
				mode = &modes[i];
			}
		}
		switch (opt) {
			case 'w':
				warn = 1;
				break;
			case 'f':
				if (devname == NULL) {
					devname = strdup(optarg);
					file = 1;
				} else {
					print_usage();
					exit(1);
				}
				break;
			case 'd':
				if (devname == NULL) {
					devname = strdup(optarg);
					file = 0;
				} else {
					print_usage();
					exit(1);
				}
				break;
			case 'm':
				mt = strtol(optarg, NULL, 10);
				if (errno == EINVAL || mt < 0) {
					print_usage();
					exit(1);
				}
				break;
			case 'c':
				pc = strtol(optarg, NULL, 10);
				if (errno == EINVAL || pc < -1) {
					print_usage();
					exit(1);
				}
				break;
			case 't':
				to = strtol(optarg, NULL, 10);
				if (errno == EINVAL || to <= 0) {
					print_usage();
					exit(1);
				} else {
					to *= 1000; // ms to us
				}
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

	if (mode != NULL) {
		if (file) {
			pcap = init_pcap_file(devname, mode);
		} else {
			pcap = init_pcap_live(devname, mode);
		}
		if (pcap != NULL) {
			run_mode(pcap, pc, mt, to, warn, !file, mode);
			pcap_close(pcap);
			err = 0;
		} else {
			err = 1;
		}
	} else {
		print_usage();
	}

	if (devname != NULL)
		free(devname);

	return err;
}
