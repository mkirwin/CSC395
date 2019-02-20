#Sandbox

## How to build Sandbox
Within the sandbox directory (where this README is located), run 'make'

## How to call sandbox. 
Usage: ./sand <--flag1 --flag2 ...> --- <program to run + all extra arguments>

Example: ./sand --exec --signal --read --- ls -a

The following are all of the flags: --fork, --exec, --signal, --socket, --read, --read-write
They must be listed before the "---" separator.
The "---" separator must come after all the flags and before the program to be run. There must be spaces between the last flag, "---", and the program to be run. 

## Capabilities
The sandbox blocks the following by default: fork, exec, signaling, socket operations, reading, and writing. 

## Additional capability and rationale
* I chose to optionally grant permission to signal other programs and to perform socket operations.
  * To enable signaling use the "--signal" flag
  * To enable socket operations use the "--socket" flag. 

## Tests 
To test the sandbox, I provided a couple programs (read, write, exec) that simply make the system calls their names denote. To test, run the following:
$ ./sand --test-name --- ./test-name 

replacing 'test-name' with either read, write, or exec.

