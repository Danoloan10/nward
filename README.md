# nward
**nward** is a modular port scan detector. Both live capture and offline PCAP files reading are supported.
Currently **UDP**, **TCP SYN**, **TCP Connect**, **TCP ACK**, **TCP Xmas**, **TCP NULL** and **TCP FIN** are supported,
but the code is designed to allow easy implementation of detection of other port scanning techniques.
It is distributed under the [GPLv3](https://github.com/Danoloan10/nward/blob/master/LICENSE) license.
# Index
- [Usage](#usage)
- [Bulding](#building)
	- [Dependencies](#dependencies)
- [Internals](#internals)
	- [Suspicious activity](#suspicious-activity)
		- [``susp_list``](#susp_list)
		- [``synned_list``](#synned_list)
	- [Modes](#modes)
		- [Adding a mode](#adding-a-mode)
# Usage
Following is a copy of the usage instructions printed by a misuse of the program:
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
# Building
The default target of the _makefile_ generates the executable
```
$ make
$ ./nward
```
## Dependencies
- [libpcap](https://www.tcpdump.org/)
- [vector](https://github.com/goldsborough/vector) (included)
# Internals
Two very important conecpts in the inner workings of **nmap** are *modes* and *suspicious activity*.
## Suspicious activity
Some attacks can be identified by capturing only one of the packets they generate,
as these exploit errors in their format &mdash; i.e.: TCP Xmas, NULL and FIN. Others generate traffic
_potentially_ suspicious but with a behaviour that could be normal in another application &mdash; i.e.: UDP,
SYN, Connect and ACK.

For the former, it is sufficient to notify each packet that passes through the filter;
for the latter this can be the cause of false positives that make the program unusable.
As a solution to this problem the data structure ``susp_list`` (_suspects list_) is offered.

Also, for some modes it is needed to remember stablished TCP connections. For this the
data structure ``synned_list`` is offered.

### ``susp_list``
``susp_list`` is a list of IP addresses or ports where each of the elements has an associated
saturation counter. The ``susp_tick_*`` functions increase the counter associated with an IP address, a port
or a tuple of both;
and only if the saturation counter of the tuple has reached its maximum it returns a value other than 0.
The maximum of the saturation counter is expected to be specified with the ``-m`` options &mdash; this value is passed
to the processing function of the mode through the ``maxticks`` field of the argument structure.

All the counters are reduced every certain period of time (_tick_). If the capture is done live
a real-time counter can be started with the ``susp_start_live_ticker`` function.
For offline captures there is no point in using such a counter;
the function ``susp_tick_offline`` should be used instead &mdash; this function uses the PCAP header
time stamp to determine whether the counters should be reduced or not.
The latter function must be called for every received package.
The _tick_ period is specified with ``-t``; this value (specified in milliseconds) is passed (as microseconds)
to the processing function of the mode through the ``usec`` field of the argument structure.

Usually, the mode considers that if the counter associated with an IP address
is saturated a scan is being conducted from that direction. If the ``-w`` option is passed to the command,
the ``warn`` field in the argument structure is active, 
usually so that the mode notifies suspicious packages as warnings
even if the meter is not saturated.

### ``synned_list``

TCP connections represented by the ``struct tcp_con`` structure are stored in this list. Appart from the 
_(IP1,IP2,P1,P2)_ tuple identifying the TCP connection, the flags ``replied`` and ``finning`` are offered. These
are used in the ACK mode to mark the connection as replied by both parties or having a FIN handshake, respectively.
The function ``synned_match`` returns a positive value if the stored connection matches the argument in the same direction;
it returns a negative value if the stored connection matches the argument in the opposite direction.

## modes
In **nward** scanning techniques are called *modes*. Each mode consists of a *filter*, a
*configuration function* and a *processing function*. The filter is a PCAP filter, such as
described on the manual page of the PCAP library in [`pcap-filter(7)`][1]

The program only allows one mode per execution; however, different nward processes do not
interfere with each other, so if you want to use several modes at once you can run the program
once per mode.
### Adding a mode
Modes are defined in the file `modes.h`, in the `modes[]` array. For each mode the following must
be specified:
- `opt`: the character which represents the mode in the program execution arguments, your short name (name)
- `filter`: a PCAP filter as specified in its manual page [`pcap-filter(7)`][1]
- `config`: a function that configures the _libpcap_ handler as needed _(optional, only for live captures)_.
- `callback`: the processing function that will be invoked for each packet that passes the; must be of type ``pcap_handler``.

To add a mode, simply add its corresponding entry in this array. The functions that
are used in the array, such as processing or configuration functions,
must be declared in the
header file ``handler/handler.h``. Any ``*.c`` code file that must be compiled as an object for
linking in the final executable must be included in the SRCS variable of the _makefile_.

The callback processing function must be of type pcap_handler. This type is part of the
PCAP. A pointer to the structure ``struct nward_hand_args`` will be passed through the ``u_char *user`` argument.
This structure contains mainly options passed through the command line.

Once the executable has been generated, the added mode can be used by using the ``-A`` option where _A_ is
the character that represents the mode as specified in its entry in the ``modes[]`` array. Obviously, this
character cannot be any of the used for other options or modes.

The functions ``notify_attack``, ``notify_warning``, ``print_warn``, ``print_scan`` and ``print_not_supported``  are provided for printing notifications, in the file ``handler/handler.h``.

[1]: https://www.tcpdump.org/manpages/pcap-filter.7.html
