#!/usr/bin/python3
from netfilterqueue import NetfilterQueue as nfq
from scapy.all import *
from Cryptodome.Cipher import AES

    # Šifrovací funkce
def encrypt(plaintext, key, mode):
	encobj = AES.new(key, AES.MODE_GCM)
	ciphertext,authTag=encobj.encrypt_and_digest(plaintext)
	return(ciphertext,authTag, encobj.nonce)


    # Šifrování paketu a nahrazení čísla protokolu v IP hlavičce za vlastní
def listener(packet):
	scapy_packet = IP(packet.get_payload())
	ip_len = scapy_packet[IP].ihl * 4
	ciphertext = encrypt(packet.get_payload()[9].to_bytes(1,"big")+packet.get_payload()[ip_len:], key, AES.MODE_GCM)
	res_packet = IP(packet.get_payload()[:ip_len])
	res_packet = res_packet/(ciphertext[2]+ciphertext[1]+ciphertext[0])
	res_packet[IP].proto = "mujPr"
	del res_packet[IP].len
	del res_packet[IP].chksum

    # Úprava obsahu paketu za šifrovaný
	packet.set_payload(bytes(res_packet))
    # Příjem šifrovaného paketu
	packet.accept()

key = bytes.fromhex("7092aeb52161089b86c5b5f2824cb529e33764a1294b7ee810b8226fc650e86b")

queue = nfq()
    # Odchyt paketů k šifrování v 1. frontě pro pakety směřující na 2. bránu
queue.bind(1, listener)
queue.run()
