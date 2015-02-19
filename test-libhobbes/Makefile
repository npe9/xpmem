CC      = gcc

HOBBES  = $(PWD)/../../hobbes/hobbes

CFLAGS  = -I../include -I$(HOBBES)
LDFLAGS = -L../lib -L$(HOBBES) -lxpmem -lhobbes -static -lm

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
