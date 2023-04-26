#!/usr/bin/python3
from netfilterqueue import NetfilterQueue as nfq
from scapy.all import *
from Cryptodome.Cipher import AES

    # Dešifrovací funkce
def decrypt(ciphertext, key, mode):
	(ciphertext, authTag, nonce) = ciphertext
	encobj = AES.new(key, AES.MODE_GCM, nonce)
	return(encobj.decrypt_and_verify(ciphertext, authTag))

def listener(packet):

    # Dešifrování paketu a pøidání originálního protokolu
	scapy_packet = IP(packet.get_payload())
	ciphertext = (scapy_packet[Raw].load[32:], scapy_packet[Raw].load[16:32], scapy_packet[Raw].load[:16])
	plaintext = decrypt(ciphertext, key, AES.MODE_GCM)
	res_packet = IP(packet.get_payload()[:scapy_packet[IP].ihl * 4])
	res_packet = res_packet/Raw(plaintext[1:])
	res_packet[IP].proto = plaintext[0]

    # Pøepoèet kontrolního souètu a délky
	del res_packet[IP].len
	del res_packet[IP].chksum

    # Zmìna obsahu paketu na šifrovaný
	packet.set_payload(bytes(res_packet))
    # Pøíjem šifrovaného paketu
	packet.accept()

key = bytes.fromhex("7092aeb52161089b86c5b5f2824cb529e33764a1294b7ee810b8226fc650e86b")

queue = nfq()
# Odchyt paketù k dešifrování v 2. frontì pro pakety s vlastním èíslem protokolu
queue.bind(2, listener)
queue.run()
