CC      = gcc
CFLAGS  = -I$(PWD)/../include
LDFLAGS = -L$(PWD)/../lib -lxpmem -static

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
