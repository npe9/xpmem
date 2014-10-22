CC             = gcc
CFLAGS         = -I$(PWD)/../include
LDFLAGS        = -L$(PWD)/../lib -lxpmem -static

all:    test_xpmem test_xpmem-attach

test_xpmem: test_xpmem.c
	$(CC) $(CFLAGS) test_xpmem.c $(LDFLAGS) -o test_xpmem

test_xpmem-attach: test_xpmem-attach.c
	$(CC) $(CFLAGS) test_xpmem-attach.c $(LDFLAGS) -o test_xpmem-attach

clean:
	rm -f test_xpmem test_xpmem-attach
