#!/usr/bin/env python
import string
from tqdm import tqdm
from pwn import *

host = 'mercury.picoctf.net'
port = 47987

io = connect(host, port)

io.recvuntil("flag: ")
encrypted_flag = io.recvuntil("\nn: ").decode().strip()
n = io.recvuntil("\ne: ").decode().strip()
e = io.recvuntil("\n").decode().strip()

def remove_segments(result, segments):
    # Remove all previously seen segments.
    for segment in segments:
        result = result.replace(segment, "")
    return result

known_segments = []
decrypted_flag = ""
print(string.printable)
switch = False
while "}" not in decrypted_flag:
    if (switch == True):
        for c in string.printable:
            current_test = decrypted_flag + c
            # print(current_test)
            io.sendlineafter("I will encrypt whatever you give me: ", current_test)
            current_encrypt_test = io.recvuntil("\n").decode().strip()
            current_encrypt_test = current_encrypt_test.replace("Here you go: ", "")
            # print(current_encrypt_test)
            current_char_rep = remove_segments(current_encrypt_test, known_segments)
            # print(current_char_rep)
            # print(known_segments)
            if current_char_rep in encrypted_flag:
                print("New Letter Found: %s+[%s]" % (decrypted_flag, c))
                decrypted_flag += c
                known_segments.append(current_char_rep)
                break
    else:
        for c in list("picoCTF{"):
            if (c == "{"):
                switch = True
            current_test = decrypted_flag + c
            # print(current_test)
            io.sendlineafter("I will encrypt whatever you give me: ", current_test)
            current_encrypt_test = io.recvuntil("\n").decode().strip()
            current_encrypt_test = current_encrypt_test.replace("Here you go: ", "")
            # print(current_encrypt_test)
            current_char_rep = remove_segments(current_encrypt_test, known_segments)
            # print(current_char_rep)
            # print(known_segments)
            if current_char_rep in encrypted_flag:
                print("New Letter Found: %s+[%s]" % (decrypted_flag, c))
                decrypted_flag += c
                known_segments.append(current_char_rep)
                break
print("Complete Flag: %s" % decrypted_flag)