LDFLAGS = -lpcap
CFLAGS  = -g

nward: nward.o nward.h xmas.c
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)
