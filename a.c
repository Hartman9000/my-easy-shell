#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

int main() {
    write(1, "hello", 5);
}