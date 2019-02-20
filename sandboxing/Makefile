CC=clang
CFLAGS= -Wall #-fsanitize=address

all: sand exec write read 

sand: sand.o
	$(CC) $(CFLAGS) -o sand sand.o
sand.o: sand.c
	$(CC) $(CFLAGS) -c sand.c

exec: exec.o
	$(CC) $(CFLAGS) -o exec exec.c
exec.o: exec.c
	$(CC) $(CFLAGS) -c exec.c


write: write.o
	$(CC) $(CFLAGS) -o write write.c
write.o: write.c
	$(CC) $(CFLAGS) -c write.c


read: read.o
	$(CC) $(CFLAGS) -o read read.c
read.o: read.c
	$(CC) $(CFLAGS) -c read.c
	

clean:
	rm sand.o read.o write.o
