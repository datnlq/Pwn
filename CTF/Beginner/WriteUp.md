# BEGINER FOR PWNER CTF : <3

## Archer <RaRCTF 2021>

First thing, chall give to us 1 file execuse ! We have to check it by cmd : file and checksec .
```
Dump of assembler code for function main:
   0x0000000000401192 <+0>:	push   rbp
   0x0000000000401193 <+1>:	mov    rbp,rsp
   0x0000000000401196 <+4>:	sub    rsp,0x10
   0x000000000040119a <+8>:	lea    rdi,[rip+0xe67]        # 0x402008
   0x00000000004011a1 <+15>:	call   0x401030 <puts@plt>
   0x00000000004011a6 <+20>:	lea    rdi,[rip+0xe8f]        # 0x40203c
   0x00000000004011ad <+27>:	mov    eax,0x0
   0x00000000004011b2 <+32>:	call   0x401050 <printf@plt>
   0x00000000004011b7 <+37>:	mov    rax,QWORD PTR [rip+0x2eb2]        # 0x404070 <stdout@@GLIBC_2.2.5>
   0x00000000004011be <+44>:	mov    rdi,rax
   0x00000000004011c1 <+47>:	call   0x401070 <fflush@plt>
   0x00000000004011c6 <+52>:	mov    rdx,QWORD PTR [rip+0x2eb3]        # 0x404080 <stdin@@GLIBC_2.2.5>
   0x00000000004011cd <+59>:	lea    rax,[rbp-0x5]
   0x00000000004011d1 <+63>:	mov    esi,0x5
   0x00000000004011d6 <+68>:	mov    rdi,rax
   0x00000000004011d9 <+71>:	call   0x401060 <fgets@plt>
   0x00000000004011de <+76>:	lea    rax,[rbp-0x5]
   0x00000000004011e2 <+80>:	lea    rsi,[rip+0xe65]        # 0x40204e
   0x00000000004011e9 <+87>:	mov    rdi,rax
   0x00000000004011ec <+90>:	call   0x4010a0 <strstr@plt>
   0x00000000004011f1 <+95>:	test   rax,rax
   0x00000000004011f4 <+98>:	je     0x40120c <main+122>
   0x00000000004011f6 <+100>:	lea    rdi,[rip+0xe54]        # 0x402051
   0x00000000004011fd <+107>:	call   0x401030 <puts@plt>
   0x0000000000401202 <+112>:	mov    edi,0x0
   0x0000000000401207 <+117>:	call   0x401090 <exit@plt>
   0x000000000040120c <+122>:	lea    rdi,[rip+0xe59]        # 0x40206c
   0x0000000000401213 <+129>:	call   0x401030 <puts@plt>
   0x0000000000401218 <+134>:	mov    eax,0x0
   0x000000000040121d <+139>:	call   0x401275 <makeshot>
   0x0000000000401222 <+144>:	lea    rdi,[rip+0xe5f]        # 0x402088
   0x0000000000401229 <+151>:	call   0x401030 <puts@plt>
   0x000000000040122e <+156>:	mov    rax,QWORD PTR [rip+0x2e33]        # 0x404068 <code>
   0x0000000000401235 <+163>:	cmp    rax,0x13371337
   0x000000000040123b <+169>:	jne    0x401247 <main+181>
   0x000000000040123d <+171>:	mov    edi,0x0
   0x0000000000401242 <+176>:	call   0x401090 <exit@plt>
   0x0000000000401247 <+181>:	lea    rdi,[rip+0xe6b]        # 0x4020b9
   0x000000000040124e <+188>:	call   0x401030 <puts@plt>
   0x0000000000401253 <+193>:	mov    rax,QWORD PTR [rip+0x2e16]        # 0x404070 <stdout@@GLIBC_2.2.5>
   0x000000000040125a <+200>:	mov    rdi,rax
   0x000000000040125d <+203>:	call   0x401070 <fflush@plt>
   0x0000000000401262 <+208>:	lea    rdi,[rip+0xe58]        # 0x4020c1
   0x0000000000401269 <+215>:	call   0x401040 <system@plt>
   0x000000000040126e <+220>:	mov    eax,0x0
   0x0000000000401273 <+225>:	leave  
   0x0000000000401274 <+226>:	ret    



-----



0x0000000000401275 <+0>:	push   rbp
   0x0000000000401276 <+1>:	mov    rbp,rsp
   0x0000000000401279 <+4>:	sub    rsp,0x10
   0x000000000040127d <+8>:	lea    rdi,[rip+0xe45]        # 0x4020c9
   0x0000000000401284 <+15>:	call   0x401030 <puts@plt>
   0x0000000000401289 <+20>:	lea    rdi,[rip+0xe50]        # 0x4020e0
   0x0000000000401290 <+27>:	call   0x401030 <puts@plt>
   0x0000000000401295 <+32>:	mov    rax,QWORD PTR [rip+0x2dd4]        # 0x404070 <stdout@@GLIBC_2.2.5>
   0x000000000040129c <+39>:	mov    rdi,rax
   0x000000000040129f <+42>:	call   0x401070 <fflush@plt>
   0x00000000004012a4 <+47>:	lea    rax,[rbp-0x8]
   0x00000000004012a8 <+51>:	mov    rsi,rax
   0x00000000004012ab <+54>:	lea    rdi,[rip+0xe57]        # 0x402109
   0x00000000004012b2 <+61>:	mov    eax,0x0
   0x00000000004012b7 <+66>:	call   0x401080 <__isoc99_scanf@plt>
   0x00000000004012bc <+71>:	mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004012c0 <+75>:	add    rax,0x500000
   0x00000000004012c6 <+81>:	mov    QWORD PTR [rbp-0x8],rax
   0x00000000004012ca <+85>:	mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004012ce <+89>:	mov    QWORD PTR [rax],0x0
   0x00000000004012d5 <+96>:	lea    rdi,[rip+0xe30]        # 0x40210c
   0x00000000004012dc <+103>:	call   0x401030 <puts@plt>
   0x00000000004012e1 <+108>:	nop
   0x00000000004012e2 <+109>:	leave  
   0x00000000004012e3 <+110>:	ret    

```




Using IDA Pro can help us to ezz read C code from ASM :vv
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [rsp+Bh] [rbp-5h]

  puts("It's battle day archer! Have you got what it takes?");
  printf("Answer [yes/no]: ", argv);
  fflush(_bss_start);
  fgets(&s, 5, stdin);
  if ( strstr(&s, "no") )
  {
    puts("Battle isn't for everyone.");
    exit(0);
  }
  puts("Awesome! Make your shot.");
  makeshot();
  puts("Hope you shot well! This will decide the battle.");
  if ( code == 322376503 )
    exit(0);
  puts("WE WON!");
  fflush(_bss_start);
  system("/bin/sh");
  return 0;
}


int makeshot()
{
  _QWORD *v1; // [rsp+8h] [rbp-8h]

  puts("Here's your arrow!");
  puts("Now, which soldier do you wish to shoot?");
  fflush(_bss_start);
  __isoc99_scanf("%p", &v1);
  v1 += 0xA0000;
  *v1 = 0LL;
  return puts("Shot!");
```



## ret2winRaRs 

In this chall, we have to uplevel++ :vv becuz chall is more interesting ! This flow is mean we enter linsense key and it return something :vv

Using IDA to understanding about chall'flow

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("Hello, welcome to the WinRaRs!");
  printf("Please enter your WinRaR license key to get access: ", 0LL);
  get_license();
  puts("Thanks for the license :)");
  return 0;
}

__int64 get_license()
{
  char v1; // [rsp+0h] [rbp-20h]

  return gets(&v1);
}

```


Using pwngdb ....


```
0x0000000000401191 <+0>:	push   rbp
   0x0000000000401192 <+1>:	mov    rbp,rsp
   0x0000000000401195 <+4>:	mov    rax,QWORD PTR [rip+0x2eb4]        # 0x404050 <stdout@@GLIBC_2.2.5>
   0x000000000040119c <+11>:	mov    ecx,0x0
   0x00000000004011a1 <+16>:	mov    edx,0x2
   0x00000000004011a6 <+21>:	mov    esi,0x0
   0x00000000004011ab <+26>:	mov    rdi,rax
   0x00000000004011ae <+29>:	call   0x401070 <setvbuf@plt>
   0x00000000004011b3 <+34>:	lea    rdi,[rip+0xe66]        # 0x402020
   0x00000000004011ba <+41>:	call   0x401030 <puts@plt>
   0x00000000004011bf <+46>:	lea    rdi,[rip+0xe7a]        # 0x402040
   0x00000000004011c6 <+53>:	mov    eax,0x0
   0x00000000004011cb <+58>:	call   0x401050 <printf@plt>
   0x00000000004011d0 <+63>:	mov    eax,0x0
   0x00000000004011d5 <+68>:	call   0x401175 <get_license>
   0x00000000004011da <+73>:	lea    rdi,[rip+0xe94]        # 0x402075
   0x00000000004011e1 <+80>:	call   0x401030 <puts@plt>
   0x00000000004011e6 <+85>:	mov    eax,0x0
   0x00000000004011eb <+90>:	pop    rbp
   0x00000000004011ec <+91>:	ret   
   
   ----
   
   0x0000000000401175 <+0>:	push   rbp
   0x0000000000401176 <+1>:	mov    rbp,rsp
   0x0000000000401179 <+4>:	sub    rsp,0x20
   0x000000000040117d <+8>:	lea    rax,[rbp-0x20]
   0x0000000000401181 <+12>:	mov    rdi,rax
   0x0000000000401184 <+15>:	mov    eax,0x0
   0x0000000000401189 <+20>:	call   0x401060 <gets@plt>
   0x000000000040118e <+25>:	nop
   0x000000000040118f <+26>:	leave  
   0x0000000000401190 <+27>:	ret  
```


## hello 




```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v4; // [rsp+0h] [rbp-58h]
  int v5; // [rsp+4Ch] [rbp-Ch]

  puts("Hello there! What is your name?");
  fflush(_bss_start);
  v5 = 0;
  gets(&v4, argv);
  if ( v5 )
    system("cat flag.txt");
  else
    printf("Well, hello %s!", &v4);
  putchar(10);
  return 0;
}

```
