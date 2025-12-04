CC = gcc
CFLAGS = -Wall -O3
LDFLAGS = -lsqlite3 -lcap-ng

TARGET = sniffer
SRCS = sniffer.c db.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
