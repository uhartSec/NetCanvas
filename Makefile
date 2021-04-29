SHELL := /bin/bash
CC=g++
CFLAGS=-pedantic -ansi -Wall -lpcap

SRC_DIR := ./src

all: netCanvas
	
netCanvas: $(SRC_DIR)/*.cpp $(SRC_DIR)/*.h
	$(CC) $(CFLAGS) -g -o netCanvas $(SRC_DIR)/*.cpp

valgrind: -netCanvas
	valgrind --tool=memcheck --leak-check=yes ./netCanvas

clean:
	rm netCanvas
