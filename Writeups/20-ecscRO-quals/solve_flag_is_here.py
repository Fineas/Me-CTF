import os
import subprocess

f = open('rockyou.txt')
data = f.read().split('\n')

for i in data:
    os.system('steghide extract -sf ./splash.jpg -p '+i)
    # print command
    # subprocess.Popen(args=['steghide', 'extract -sf ./splash.jpg -p '+i], shell=True)
    print '>>',i
    # print subprocess.check_output(command)
    # raw_input('??')
