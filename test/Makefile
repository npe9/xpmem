CC             = gcc
CFLAGS         = -I$(PWD)/../include
LDFLAGS        = -L$(PWD)/../lib -lxpmem

TARGET        = test_xpmem
SOURCES       = test_xpmem.c
OBJECTS       = $(SOURCES:.c=.o)


all:    $(TARGET) 

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

clean:
	rm -f $(TARGET) $(OBJECTS)
