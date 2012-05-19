CC     = gcc
CFLAGS = -Wall -O2 -g -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
LDLIBS =

TARGET = tspick
OBJS   = tspick.o

.SUFFIXES: .c .o

$(TARGET): $(OBJS)
	$(CC) $(LDLIBS) -o $(TARGET) $^

.c.o:
	$(CC) $(CFLAGS) -c $<

.PHONY: clean
clean:
	$(RM) $(TARGET) $(OBJS)
