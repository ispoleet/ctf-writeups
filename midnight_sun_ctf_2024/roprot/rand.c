#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    srand(atoi(argv[1]));

    int *ptr = malloc(0x1000);
    for (int i=0; i<0x570 >> 2; ++i) {
        ptr[i] = rand();
    }

    char *p = (char *)ptr;
    for (int i=0; i< 0x570; ++i) {
        printf("%02X\n", (p[i] & 0xFF));
    }

    return 0;
}
