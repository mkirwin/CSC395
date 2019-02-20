#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

int main() {
  open(".", O_RDONLY);
  printf("(read.c) Success: Read operation completed.\n");
  return 0;
}
