# Makefile for tests

TESTS = re_enc_test
OBJS = re_enc_test.o
LIBRARY = -lgmp -lcrypto -ltepla

.PHONY: all
all: $(TESTS)

re_enc_test: re_enc_test.o ../prenc.o
	$(CC) $(CFLAGS) $^ $(LIBRARY) -o $@

re_enc_test.o: re_enc_test.c
	$(CC) -c $(CFLAGS) $^

.PHONY: clean
clean:
	$(RM) $(OBJS) $(TESTS)
