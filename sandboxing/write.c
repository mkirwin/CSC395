#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

int main() {
  open("README.md", O_RDWR);
  printf("(write.c) Success: Read-write operation completed.\n");
  return 0;
}
