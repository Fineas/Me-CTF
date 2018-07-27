#!/usr/bin/env python

from pwn import *
import sys
import argparse
import json

bin_name = ''
binary = ''

# =============================
# USEFUL FUNCTIONS
# =============================

def open_binary():
    global bin_name
    global binary
    log.info('Opening Binary')

    if '-b' in sys.argv:
        bin_name = sys.argv[sys.argv.index('-b')+1]
        binary = ELF(bin_name)
        log.info('Binary name= '+bin_name)

    elif '--binary' in sys.argv:
        bin_name = sys.argv[sys.argv.index('--binary')+1]
        binary = ELF(bin_name)
        log.info('Binary name= '+bin_name)

    else:
        log.info('No Binary specified')

def export_data():
    print binary.checksec()
    print binary.plt
    print binary.got


def get_plt():
    PLT = str(binary.plt).replace('{', '').replace('}', '').replace("u'", '').replace("':", '=').split(',')
    #log.info(PLT)
    return PLT

def get_got():
    GOT = str(binary.got).replace('{', '').replace('}', '').replace("u'", '').replace("':", '=').split(',')
    #log.info(GOT)
    return GOT

# =============================
# PARSE ARGUMENTS
# =============================
parser = argparse.ArgumentParser(description='Exploit the bins.')
parser.add_argument('--binary', '-b', action=open_binary() )
args = parser.parse_args()

f = open('/home/..../solve_binaries.py','rb')
data = f.read()
f.close()
new_file = data[:data.index("    ''')")]

# =============================
# REPLACE FILE NAME AND ARCH
# =============================
new_file = new_file.replace("context.arch = 'amd64'", "context.arch = '"+binary.get_machine_arch()+"'")
new_file = new_file.replace("program_name = './program_name'","program_name = './"+bin_name+"'")
new_file += "    ''')\n\n"

# =============================
# WRITE PLT SECTION
# =============================
PLT = get_plt()
new_file += '# ============ PLT =========== #\n\n'
for i in PLT:
    new_file += i[1 : i[1:].index('=')+1]
    new_file += '@PLT = '
    new_file += hex(int(i[i[1:].index('=')+2:],10))
    new_file += '\n'

# =============================
# WRITE GOT SECTION
# =============================
GOT = get_got()
new_file += '\n# ============ GOT =========== #\n\n'
for i in GOT:
    new_file += i[1 : i[1:].index('=')+1]
    new_file += '@GOT = '
    new_file += hex(int(i[i[1:].index('=')+2:],10))
    new_file += '\n'

# =============================
# WRITE REST OF FILE
# =============================
new_file += data[data.index("    ''')")+len("    ''')")+1:]

# =============================
# WRITE TO FILE
# =============================
f = open('solution.py','wb')
f.write(new_file)
f.close()
