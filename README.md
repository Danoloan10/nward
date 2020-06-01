# nward
nward is a modular port scan detector. Following is a copy of the usage printed by a misuse of the program:
```
Usage:
	nward [options] -mode
  
All options and arguments following the mode argument are ignored

options:
	-c N - analyse up to N packets (0 or less for infinity, default: 0)
	-d «device»
	       perform live session capturing traffic from «device».
	       If not provided, chooses the first found. Incompatible with -f
	-f «file»
	       perform offline session reading the PCAP file «file». Incompatible with -d
	-l   - list devices available for live session and exit (discards all other options)
	-m M - tolerate up to M suspicious events (must be non-negative, default 10)
	-t T - a tick will last T milliseconds. Each tick a suspicious event is forgotten
	       for every source IP address. In offline sessions, ticks are triggered by
	       the packet reads and timeouts are based on the timestamps of the packets
	       (must be positive, default 100)
	-w   - print scan warnings when suspicious
mode:
	-A - ward from ACK scans
	-F - ward from FIN scans
	-N - ward from NULL scans
	-S - ward from SYN scans
	-T - ward from Connect scans
	-U - ward from UDP scans
	-X - ward from Xmas scans
Example:
	nward -f file.pcap -c 10 -m 10 -t 2000 -F
  ```
