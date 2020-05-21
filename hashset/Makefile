CFLAGS=-std=c89 -pedantic -Wall -Wextra -Werror -ggdb3 -O0

libhset.a: hashset.o
	$(AR) cr $@ $^

hashset.o: hashset.c
	$(CC) $(CFLAGS) -c hashset.c -o $@

clean:
	rm -f *.o test

reformat:
	astyle --mode=c \
               --quiet \
               --style=1tbs \
               --indent=spaces=4 \
               --indent-col1-comments \
               --max-instatement-indent=78 \
               --pad-oper \
               --pad-header \
               --add-brackets \
               --align-pointer=name \
               *.[ch]

.PHONY: clean reformat
