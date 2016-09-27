CC = gcc
CFLAGS = -O0 -g -I../openssl/include

all: test_client

test_client: test_client.o
	$(CC) $(CFLAGS) $^ -L../openssl -o test_client -lssl -lcrypto -ldl

clean:
	rm -f test_client test_client.o
