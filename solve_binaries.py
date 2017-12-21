#!/usr/bin/env python

from pwn import *
import sys
import time
import argparse
import string

# ========================== SETTINGS ========================== #

context.arch = 'i386'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
# ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.log_level = 'INFO'

# ========================== TEMPLATE ========================== #

WORD = 'A'*4    # 32bit
DWORD = 'X'*8   # 64bit

program_name = './program_name'
remote_server = 'ip of the server'
PORT = 'number'

parser = argparse.ArgumentParser(description='Exploit the bins.')
parser.add_argument('--dbg'   , '-d', action="store_true")
parser.add_argument('--remote', '-r', action="store_true")
args = parser.parse_args()

if args.remote:
    p = remote(remote_server, 4012)
else:
    p = process(program_name)

if args.dbg:
    gdb.attach(r, '''
    vmmap
    b *main
    ''')

payload = ''
data = ''

def console_output():
    data = p.recv(2000)
    # print data

def send_data(payload):
    # print '[*] payload'
    p.sendline(payload)

def wait_for_prompt(sentence):
  print r.recvuntil(sentence)

# ====================== FLOW OF PROGRAM ======================= #

if __name__ == "__main__":



    p.interactive()
