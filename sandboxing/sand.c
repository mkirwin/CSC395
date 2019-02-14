#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>

void handle_forbidden(size_t syscall_num, char* error_msg, pid_t pid);
void parse_args(int argc, char** argv);

void parse_args(int argc, char** argv) {
/*
     printf("******%d arguments total.********\n", argc);
     for (int i = 0; i <= argc; i++) {
     printf(argv[i]);

     if (i < argc-1) printf(", ");
     if (argv[i] == NULL) printf("NULL");
     }
     printf("\n");
*/
  if (argc > 1) {
    if (execvp(argv[1], &(argv[1]))) {
      perror("execvp failed");
      exit(2);
    }
  } else {
    printf("No program selected to run in sandbox. No arguments given to sand.\n");  
  }

}

int main(int argc, char** argv) {
  // Call fork to create a child process
  pid_t child_pid = fork();
  if(child_pid == -1) {
    perror("fork failed");
    exit(2);
  }

  // If this is the child, ask to be traced
  if(child_pid == 0) {
    if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
      perror("ptrace traceme failed");
      exit(2);
    }

    // Stop the process so the tracer can catch it
    raise(SIGSTOP);

    // TODO: Do some work in the sandboxed child process here
    //       As an example, just run `ls`.

    parse_args(argc, argv); // ** HERE ***
/*
    if (argc > 1) {

      if (execvp(argv[1], &(argv[1]))) {
        perror("execvp failed");
        exit(2);
      }
    } else {
      perror("No program provided to sandbox/Not enough arguments.");
    }
       if (execlp("ls", "ls", "-a", NULL)) {
       perror("execlp failed");
       exit(2);
       }
       */

  } else { // Parent Code
    // Wait for the child to stop
    int status;
    int result;
    do {
      result = waitpid(child_pid, &status, 0);
      if(result != child_pid) {
        perror("waitpid failed");
        exit(2);
      }
    } while(!WIFSTOPPED(status));

    // We are now attached to the child process
    printf("Attached!\n");

    // Now repeatedly resume and trace the program
    bool running = true;
    bool isFirstRun = true; // Needed to allow first exec.
    int last_signal = 0;
    while(running) {
      // Continue the process, delivering the last signal we received (if any)
      if(ptrace(PTRACE_SYSCALL, child_pid, NULL, last_signal) == -1) {
        // TODO: does the ptrace call happen here, and this is just error catching?
        perror("ptrace CONT failed");
        exit(2);
      }

      // No signal to send yet
      last_signal = 0;

      // Wait for the child to stop again
      if(waitpid(child_pid, &status, 0) != child_pid) {
        perror("waitpid failed");
        exit(2);
      }

      // Wait for something to happen in the child process. 

      if(WIFEXITED(status)) {
        printf("Child exited with status %d\n", WEXITSTATUS(status));
        running = false;
      } else if(WIFSIGNALED(status)) {
        printf("Child terminated with signal %d\n", WTERMSIG(status));
        running = false;
      } else if(WIFSTOPPED(status)) {
        // Get the signal delivered to the child
        last_signal = WSTOPSIG(status);

        // If the signal was a SIGTRAP, we stopped because of a system call
        if(last_signal == SIGTRAP) {
          // Read register state from the child process
          struct user_regs_struct regs;
          if(ptrace(PTRACE_GETREGS, child_pid, NULL, &regs)) {
            perror("ptrace GETREGS failed");
            exit(2);
          }

          // Get the system call number
          size_t syscall_num = regs.orig_rax;

          // Check permissions TODO: Do i want to check here, or elsewhere?
          bool canFork = true;
          bool canExec = true; // TODO: allow first exec.
          bool canRead = true; // TODO: check directory?
          bool canWrite = true; // TODO: Check rw and directory?
          bool canSignal = true;

          // TODO: if disallowed syscall_num, then run through forbidden. Else, run the system call.
          switch (syscall_num) {

            case 0 : // (read) Read file
              if (!canRead) {
                handle_forbidden(syscall_num, "Attempted to read with insufficient permission.\n", child_pid);
              } else {
                printf("PERMISSION GRANTED TO READ\n");
              }
              break;

            case 1 : // (write) Write file
              if (!canWrite) {
                handle_forbidden(syscall_num, "Attempted to write with insufficient permission.\n", child_pid);
              } else {
                printf("PERMISSION GRANTED TO WRITE\n");
              }
              break;

            case 80 : // (chdir) Change directory
              handle_forbidden(syscall_num, "Attempted to change directories with insufficient permission.\n", child_pid);

              break;

            case 83 : // (mkdir) Make directory  
              handle_forbidden(syscall_num, "Attempted to make a directory with insufficient permission.\n", child_pid);
              break;

            case 197 ... 198 : // (removexattr, lremovexattr)
              handle_forbidden(syscall_num, "Attempted to remove a file with insufficient permission.\n", child_pid);
              break;

              // TODO: Sending signals to other processes
            case 62 : // (kill) Send signals to other processes
              if (!canSignal) {
                handle_forbidden(syscall_num, "Attempted to send signal to another process with insufficient permission.\n", child_pid);
              } else {
                printf("PERMISSION GRANTED TO SEND SIGNALS TO OTHER PROCESSES\n");
              }
              break;

              // fork, or maybe clone?
            case 56 ... 58 :
              if (!canFork) { // (fork, clone)
                handle_forbidden(syscall_num, "Attempted to fork a process with insufficient permission.\n", child_pid);
              } else {

                printf("PERMISSION GRANTED TO FORK\n");
              }
              break;

            case 59 : // (exec) 
              if (!canExec && !isFirstRun) {
                handle_forbidden(syscall_num, "Attempted to execute a process with insufficient permission.\n", child_pid);
              } else {
                if (isFirstRun) {
                  isFirstRun = false;
                  printf("SWITCHING FROM FIRST RUN.\n");
                }
                printf("PERMISSION GRANTED TO EXEC\n");
              }
              break;

            case 41 : // (socket) TODO: Do i need to block whole range? thru 55
              handle_forbidden(syscall_num, "Attempted to perform a socket operation with insufficient permission.\n", child_pid);
              break;

          }


          // Print the systam call number and register values
          // The meanings of registers will depend on the system call.
          // Refer to the table at https://filippo.io/linux-syscall-table/
          /*
             printf("Program made system call %lu.\n", syscall_num);
             printf("  %%rdi: 0x%llx\n", regs.rdi);
             printf("  %%rsi: 0x%llx\n", regs.rsi);
             printf("  %%rdx: 0x%llx\n", regs.rdx);
             printf("  ...\n");
             */
          last_signal = 0;
        }
      }
    }

    return 0;
  }
}

void handle_forbidden(size_t syscall_num, char* error_msg, pid_t pid) {
  printf("Attempted to ");
  printf("%s", error_msg);
  printf("without sufficient permission.\n");
  kill(pid, SIGKILL);
  exit(126); 
}

