#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/syscall.h>

int main() {
    pid_t pid = syscall(SYS_fork);
    if (pid == 0) {
        printf("Child process\n");
        fflush(stdout);
    } else {
        wait(0);
        printf("Parent process\n");
        fflush(stdout);
    }
    return 0;
}