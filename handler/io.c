#include "handler.h"

void print_warn (struct timeval ts) 
{
	printf("( %ld.%04ld ) - warning - ", ts.tv_sec, ts.tv_usec/100);
}

void print_scan (struct timeval ts)
{
	printf("[ %ld.%04ld ] * SCAN * ", ts.tv_sec, ts.tv_usec/100);
}

void print_not_supported (struct timeval ts, int vers)
{
	print_warn(ts);
	printf(" packet not analysed, IP version (%d) not supported\n", vers);
}

void notify_warning (const char *msg, struct timeval ts, ipv4_addr attacker, ipv4_addr victim, int port) {
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

void notify_attack (const char *msg, struct timeval ts, ipv4_addr attacker, ipv4_addr victim, int port) {
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
