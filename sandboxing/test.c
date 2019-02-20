#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void readForbiddenTest() {
  execlp("./sand", "./sand", "--exec", "--read-write", "---", "./read", NULL);
}

void readWriteForbiddenTest() {
  execlp("./sand", "./sand", "--exec", "---", "./write", NULL);
}

void execForbiddenTest() {
  execlp("./sand", "./sand", "---", "./exec", NULL);
}

int main(int argc, char** argv) {
  execForbiddenTest();
  readWriteForbiddenTest();
  readForbiddenTest();
  return 0;
}
