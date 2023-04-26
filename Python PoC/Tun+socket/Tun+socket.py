#!/usr/bin/python3
import socket
from scapy.all import *
from Cryptodome.Cipher import AES
import logging as LOGGER
from concurrent.futures.thread import ThreadPoolExecutor
from ipaddress import IPv4Address
import fcntl, time
import os
import struct
import subprocess
from array import array
from multiprocessing import Queue, Process

    # Informace komunikujících stran
HOST = "10.0.2.20"
HOST2 = "10.0.2.10"
PORT = 42069

    # Šifrovací funkce
def encrypt(plaintext, key, mode):
	encobj = AES.new(key, AES.MODE_GCM)
	ciphertext,authTag=encobj.encrypt_and_digest(plaintext)
	return(ciphertext,authTag, encobj.nonce)

    # Dešifrovací funkce
def decrypt(ciphertext, key, mode):
	(ciphertext, authTag, nonce) = ciphertext
	encobj = AES.new(key, AES.MODE_GCM, nonce)
	return(encobj.decrypt_and_verify(ciphertext, authTag))

    # Šifrování paketu a poslání přes UDP
def sifrfun(packet):
	ciphertext = encrypt(packet, key, AES.MODE_GCM)
	enc = ciphertext[2] + ciphertext[1] + ciphertext[0]
	s.sendto(enc, (HOST2,PORT))
    
    # Dešifrování paketu
def desifrfun(packet):
	try:
		ciphertext = (packet[32:], packet[16:32], packet[:16])
		tun.write(bytes(decrypt(ciphertext, key, AES.MODE_GCM)))
	except:
		print("Kontrola selhala")

    # Agregace funkcí pro šifrovací proces
def sifruj():
	while 1:
		packet = tun.read(1428)
		sifrfun(packet)

    # Agregace funkcí pro dešifrovací proces
def desifruj():
	while 1:
		data, addr = s.recvfrom(1500)
		desifrfun(data)
        
    # Vytvoření přístupu do virtuálního rozhraní
def openTun(tunName):
	TUNSETIFF = 0x400454ca
	IFF_TUN = 0x0001
	IFF_NO_PI = 0x1000

	tun = open('/dev/net/tun', 'r+b', buffering=0)
	ifs = struct.pack('16sH22s', tunName, IFF_TUN | IFF_NO_PI, b'')
	fcntl.ioctl(tun, TUNSETIFF, ifs)
	return tun


if __name__ == '__main__':
	key = bytes.fromhex("7092aeb52161089b86c5b5f2824cb529e33764a1294b7ee810b8226fc650e86b")
	tun = openTun(b'tun0')
    
    # Vytvoření UDP spojení
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind((HOST,PORT))
	print("Pripojeno")
    
    # Vytvoření procesu pro šifrování
	p = Process(target=sifruj, args=())
	p.start()
    
    # Spuštění dešifrování
	desifruj()
