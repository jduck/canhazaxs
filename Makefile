CC = gcc
CFLAGS = -Wall -ggdb

all: bins/chax64 bins/charm

bins/chax64: canhazaxs.c
	$(CC) $(CFLAGS) -o $@ $^

bins/charm: canhazaxs.c
	$(HOME)/android/dev/agcc.sh -o $@ $^

