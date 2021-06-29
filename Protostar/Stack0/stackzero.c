/*gcc -o stack0 stackzero.c -fno-stack-protector -g -z execstackgcc -o stack0 stackzero.c -fno-stack-protector -g -z execstack*/

#include<stdlib.h>
#include<unistd.h>
#include<stdio.h>

int main(int argc, char **argv)
{
	volatile int modified;
	char buffer[64];

	modified = 0;
	gets(buffer);

	if(modified != 0 )
		printf("You changed the 'modified' variable \n");
	else
		printf("Try again?\n");
}
