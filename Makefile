CC = gcc
CFLAGS = -Wall -Werror -std=gnu99 -pthread -I

all: dbclient dbserver
clean:
    rm -f dbclient dbserver

dbclient: dbclient.c msg.h
    $(CC) -o dbclient dbclient.c

dbserver: dbserver.c msg.h
    $(CC) -o dbserver dbserver.c
