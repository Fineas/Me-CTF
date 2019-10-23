from pwn import *
from PIL import Image
import numpy as np
from qr import *
from pyzbar.pyzbar import *
import qrcode


white = '#'.encode()
black = ' '.encode()

def makeqr(data):
    qr = qrcode.QRCode(
        version=2,
        box_size=1,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white")

def qr_to_payload(qr):
    payload = []
    arr = np.array(qr)
    row = list()
    print('[*] SIZE =',arr.shape)
    for i in arr:
        row =[]
        for j in i:
            if j:
                row.append(white)
            else:
                row.append(black)
        payload.append(row)
    return payload

def write_command(cmd):
    print('[*] Encoded Data =', cmd)
    ls_qr = makeqr(cmd)
    arr = qr_to_payload(ls_qr)
    print('[*] QR CODE ')
    payload = ''
    for i in arr:
        for j in i:
            payload += j.decode().replace('#','█')
        payload += '\n'

    return payload


if __name__ == "__main__":
    print (' ')
    print ('[1] Generate QR')
    print ('[2] Convert ASCII QR to .bmp')
    option = input('> ')
    if option == '1':
        print ('[*] Enter String:')
        data = input('> ')
        QR = write_command(data.strip())
        print (QR)
    elif option == '2':
        print ('TODO')
    else:
        print ('[!] Invalid option')
