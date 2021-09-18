#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char **argv) 
{
    int offset = atoi(argv[1]);
    time_t t = time(NULL);
    for(int i=0;i<3;++i) {
        srand(t + offset + i);
        printf("%d ", rand() % 0x100000 & 0xffffffff);
    }
    puts("\n");
    return 0;
}