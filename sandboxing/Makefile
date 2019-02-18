CC=clang
CFLAGS= -Wall #-fsanitize=address

sand: sand.o
	$(CC) $(CFLAGS) -o sand sand.o

sand.o: sand.c
	$(CC) $(CFLAGS) -c sand.c

clean:
	rm sand.o
