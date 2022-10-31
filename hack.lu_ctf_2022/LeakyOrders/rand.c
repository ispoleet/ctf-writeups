#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[]) {
	int max = __libc_current_sigrtmax();
	int min = __libc_current_sigrtmin();

//	srand(time(0) + atoi(argv[1]));
	srand(atoi(argv[1]));
//	srand(0x00000000635C9CA8);
	
	int a = rand() % (max - min + 1) + min;
	int b = rand() % (max - min + 1) + min;
	int c = rand() % (max - min + 1) + min;

//	printf("minmax: 0x%X 0x%X\n", min, max);
	
//	srand(atoi(argv[1])+1);
	
	int d = rand() % (max - min + 1) + min;
	int e = rand() % (max - min + 1) + min;
	int f = rand() % (max - min + 1) + min;

//	printf("%d %d %d %d %d %d\n", a, b, c, d, e, f);
	printf("%d %d %d\n", a, b, c);

	return 0;
}
