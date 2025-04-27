#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

int main() {
    void *addr = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    printf("Memory mapped at: %p\n", addr);
    if (addr != MAP_FAILED) munmap(addr, 4096);
    return 0;
}