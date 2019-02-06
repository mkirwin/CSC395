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
        //if(execlp("ls", "ls", NULL)) {
        if (execlp("pwd", "pwd", NULL)) {
            perror("execlp failed");
            exit(2);
        }

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
                    char* error_msg = "Attempted to %s with insufficient permission";
                    switch (syscall_num) {

                        case 0 : // (read) Read file
                            handle_forbidden(syscall_num, "Attempted to read with insufficient permission.\n", child_pid);
                            break;

                        case 1 : // (write) Write file
                            handle_forbidden(syscall_num, "Attempted to write with insufficient permission.\n", child_pid);
                            break;

                        case 80 : // (chdir) Change directory
                            handle_forbidden(syscall_num, "Attempted to change directories with insufficient permission.\n", child_pid);
                            break;

                        case 83 : // (mkdir) Make directory  
                            handle_forbidden(syscall_num, "Attempted to make a directory with insufficient permission.\n", child_pid);
                            break;
                        
                        case 197 ... 198 : // (removexattr, lremovexattr)
                            handle_forbidden(syscall_num, "Attempted to remove a file with insufficient permission.\n", child_pid);

                    }


                    // Print the systam call number and register values
                    // The meanings of registers will depend on the system call.
                    // Refer to the table at https://filippo.io/linux-syscall-table/
                    printf("Program made system call %lu.\n", syscall_num);
                    printf("  %%rdi: 0x%llx\n", regs.rdi);
                    printf("  %%rsi: 0x%llx\n", regs.rsi);
                    printf("  %%rdx: 0x%llx\n", regs.rdx);
                    printf("  ...\n");

                    last_signal = 0;
                }
            }
        }

        return 0;
    }
    }

    void handle_forbidden(size_t syscall_num, char* error_msg, pid_t pid) {
        printf("%s", error_msg);
        kill(pid, SIGKILL);
        exit(126); 
    }

