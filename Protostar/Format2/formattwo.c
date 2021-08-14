#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;



void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);s
  printf(buffer);
  
  if(target == 64) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %d :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}

//gcc -m32 -o format2 formattwo.c -fno-stack-protector -g -z execstack -W -no-pie

