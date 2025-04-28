#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

int main() {
	printf("Hello, NJU!\n");
	fflush(stdout);
	printf("hello");
	fflush(stdout);
	printf(" world\n");
	fflush(stdout);
	return 0;
}
