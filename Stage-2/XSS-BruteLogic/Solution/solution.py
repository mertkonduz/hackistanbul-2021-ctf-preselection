#!/usr/bin/env python

from PIL import Image
import cv2
from Crypto.Cipher import AES
import hashlib
import getpass
import sys

def decrypt():
        print("Decrypting")

        path = raw_input("Enter full path of image : ")
        path = str(path)
        img = cv2.imread(path)
        binary = ""
        list = []
        
        lenght = 0
        lenght = int(img[-1][-1][0])
        lenght += int(img[-1][-1][1])

        lenght += int(img[-1][-1][2])

        lenght += int(img[-1][-2][0])
        lenght += int(img[-1][-2][1])
        lenght += int(img[-1][-2][2])
        #print(lenght)
        count = 0

        for i in range(len(img)):
            for j in range(len(img[i])):
                for x in range(len(img[i][j])):
                    if count == lenght:
                        break
                    count += 1
                    if img[i][j][x] % 2 == 0:
                        binary = binary+"0"
                    elif img[i][j][x] % 2 != 0:
                        binary = binary+"1"

        #print(binary)

        a = 8
        b = 0
        for i in range(len(binary) / 8):
            list.append(binary[b:a])
            b = a
            a += 8

        liste = []

        for i in range(len(list)):
                a = str(list[i])
                doc = int(a, 2)
                char = chr(doc)
                liste.append(char)

        word = ""
        word = ''.join(liste)

        password = str("'-alert(1)-'")
        deneme = word.decode('hex')
        key = hashlib.md5(password)
        k = key.hexdigest()
        cipher = AES.new(k,AES.MODE_ECB) # AES MODE
        dencrypted_data = cipher.decrypt(deneme)
        print(dencrypted_data)

decrypt()
