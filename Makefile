CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap

OBJ = main.o sniffer.o packet_handler.o

all: sniffer

sniffer: $(OBJ)
	$(CC) $(CFLAGS) -o sniffer $(OBJ) $(LDFLAGS)

main.o: main.c sniffer.h
	$(CC) $(CFLAGS) -c main.c

sniffer.o: sniffer.c sniffer.h
	$(CC) $(CFLAGS) -c sniffer.c

packet_handler.o: packet_handler.c packet_handler.h
	$(CC) $(CFLAGS) -c packet_handler.c

clean:
	rm -f *.o sniffer
