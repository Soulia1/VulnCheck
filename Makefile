CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11
TARGET  = vulncheck

all: $(TARGET)

$(TARGET): vulncheck.c
	$(CC) $(CFLAGS) -o $(TARGET) vulncheck.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
