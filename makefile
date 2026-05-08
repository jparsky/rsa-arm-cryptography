#
#Program Name: makefile
#Author: Team 7
#Date: 5.2.26
#Purpose: To compile the main.s file into an executable
#


All: main
LIB=funcLib.o

CC=gcc

main: main.o $(LIB)
	$(CC) $@.o $(LIB) -g -o $@

.s.o:
	$(CC) $(@:.o=.s) -g -c -o $@
