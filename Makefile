CC = gcc
CFLAGS = -Wall -ggdb

all: bins/chax64 bins/charm

viandk:
	ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk

bins/chax64: canhazaxs.c
	$(CC) $(CFLAGS) -o $@ $^

bins/charm: canhazaxs.c
	$(HOME)/android/dev/agcc.sh -o $@ $^

