CC             = gcc
AR             = ar
CFLAGS         = -fPIC -I$(PWD)/../include

TARGET        = libxpmem.so
TARGET_STATIC = libxpmem.a


SOURCES       = libxpmem.c
OBJECTS       = $(SOURCES:.c=.o)

all: $(TARGET) $(TARGET_STATIC)

$(TARGET): $(OBJECTS)
	$(CC) -fPIC $(CFLAGS) -o $(TARGET) $(OBJECTS) -shared

$(TARGET_STATIC): $(OBJECTS) $(TARGET)
	$(AR) rcs -o $(TARGET_STATIC) $(OBJECTS)

clean:
	rm -f $(TARGET) $(TARGET_STATIC) $(OBJECTS)
