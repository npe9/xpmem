CC      = gcc

#xpmem   = $(HOME)/tmp/xpmem-github/xpmem
xpmem   = $(PWD)/../
CFLAGS  = -Wall -Werror -I$(xpmem)/include
LDFLAGS = -L../lib -lxpmem -static

SRCS   = $(shell ls *.c)
PROGS  = $(patsubst %.c,%,$(SRCS))
TARGET = $(PROGS)

.PHONY: all 
all: $(TARGET)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
 
.PHONY: clean
clean:
	rm -f $(PROGS) 
