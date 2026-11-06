CC ?= gcc
CPPFLAGS += -Iinclude -D_DEFAULT_SOURCE
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
LDLIBS += -lssl -lcrypto

COMMON = src/wire.c src/policy.c src/matchq.c

.PHONY: all clean test
all: inline-device

inline-device: $(COMMON) src/device.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@ $(LDLIBS)

test-wire: $(COMMON) tests/test_wire.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@ $(LDLIBS)

test: test-wire
	./test-wire

clean:
	rm -f inline-device test-wire
