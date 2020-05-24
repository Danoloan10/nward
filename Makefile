LDFLAGS = -lpcap -lpthread
CFLAGS  = -g -I. -Wall -MMD -MP

SRCS := nward.c
SRCS += $(wildcard data/*.c)
SRCS += $(wildcard handler/*.c)
SRCS += $(wildcard vector/*.c)

OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)
TARG = nward

$(TARG): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

clean:
	$(RM) $(OBJS) $(DEPS) $(TARG)

-include $(DEPS)

.PHONY: clean
