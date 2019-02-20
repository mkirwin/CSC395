#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

int main() {
  execlp("ls", "ls", NULL);
  printf("(exec.c) Success: Exec of program `ls` completed.\n");
  return 0;
}
