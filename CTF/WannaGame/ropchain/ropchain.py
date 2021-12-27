from pwn import *

BIN = "./ropchain"


def exploit():
	payload = b"aa"



if __name__ == '__main__':
	io = process(BIN)
	exploit()