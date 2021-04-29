SHELL := /bin/bash
CC=g++
CFLAGS=-pedantic -ansi -Wall -lpcap

all: netCanvas
	
netCanvas: main.cpp
	$(CC) $(CFLAGS) -g -o netCanvas main.cpp address.cpp interface.cpp

valgrind: netCanvas
	valgrind --tool=memcheck --leak-check=yes ./netCanvas

clean:
	rm netCanvas
