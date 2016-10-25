# Makefile

LIBRARY = -lcrypto -lgmp -ltepla
OBJS = prenc.o
CC := gcc
TEST_DIR = test/
TESTS = re_enc_test

.PHONY: all
all: prenc.o $(TESTS)

re_enc_test:
	cd test; make

prenc.o: prenc.c prenc.h
	$(CC) -c $(CFLAGS) $<

prenc.c: prenc.h

.PHONY: clean
clean:
	$(RM) $(OBJS); cd $(TEST_DIR); make clean

