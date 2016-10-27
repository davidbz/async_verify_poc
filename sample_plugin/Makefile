-include config.mk
ifeq ($(PREFIX),)
$(error PREFIX not configured)
endif

CC = gcc
CFLAGS = -fPIC -I$(PREFIX)/include
LDFLAGS = -L$(PREFIX)/lib

async_verify.so: async_verify.o
	$(CC) $(LDFLAGS) async_verify.o -shared -o async_verify.so -lssl

.PHONY: install
install: async_verify.so
	cp async_verify.so $(PREFIX)/libexec/trafficserver

.PHONY: clean
clean:
	rm -f async_verify.so async_verify.o

