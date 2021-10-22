#include <stdio.h>

int x = 0xc0ffee;
int main(void) {
    char buf[160];
    scanf("%159s", buf);
    if (x == 0xc0ffee) {
        printf(buf);
        x = 0;
    }
    puts("bye");
}

0x7ffff7a2d840

x = 0x404048
0x7fffffffdf40dis