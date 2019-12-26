from termcolor import *
import sys
from tabulate import tabulate


table_head = [colored('%rax','red'), colored('System call','green'), colored('%rdi','green'), colored('%rsi','green'), colored('%rdx','green'), colored('%r10','green'), colored('%r8','green'), colored('%r9','green')]
table_data = []

f = open('data.txt')
data = f.read()
for i in data.split('\n'):
    table_data.append(i.split('\t\t\t')[0].split('\t'))

output_data = table_data

if len(sys.argv) > 1:
    output_data = []
    for i in sys.argv[1:]:
        for j in table_data:
            if i in j[1]:
                j[0] = colored(j[0],"blue")
                j[1] = j[1].replace(i,colored(i,"yellow"))
                output_data.append(j)



print (tabulate(output_data, table_head, tablefmt="grid"))
