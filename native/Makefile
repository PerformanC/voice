CC       = gcc
CFLAGS   = -std=c99 -Wall -Wextra -Wpedantic -O2 -g
LDLIBS   = -lsodium

.PHONY: all clean test

all: libvoice_send.a

libvoice_send.a: voice_send.o
	ar rcs $@ $^

voice_send.o: voice_send.c voice_send.h
	$(CC) $(CFLAGS) -c -o $@ src/voice_send.c
