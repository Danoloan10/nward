LDFLAGS = -Lhashset -lpcap -lhset -lpthread
CFLAGS  = -g -Ihashset -Wall

nward: nward.o handler.o
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

nward.o: nward.c nward.h modes.h handler.h
	$(CC) -c -o $@ $< $(LDFLAGS) $(CFLAGS)

handler.o: handler.c modes.h head.h ipv4_head.h susp.h
	$(CC) -c -o $@ $< $(LDFLAGS) $(CFLAGS)

clean:
	$(RM) *.o nward

.PHONY: clean
