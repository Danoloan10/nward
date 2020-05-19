LDFLAGS = -lpcap
CFLAGS  = -g

nward: nward.o
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)
