#!/usr/bin/python3
from netfilterqueue import NetfilterQueue as nfq
from scapy.all import *
from Cryptodome.Cipher import AES

    # Dešifrovací funkce
def decrypt(ciphertext, key, mode, asociated_data):
	(ciphertext, authTag, nonce) = ciphertext
	encobj = AES.new(key, AES.MODE_GCM, nonce)
	encobj.update(asociated_data)
	return(encobj.decrypt_and_verify(ciphertext, authTag))

def listener(packet):
	# Dešifrování paketu a přidání originálního protokolu
	try:
		scapy_packet = IP(packet.get_payload())
		ip_len = scapy_packet[IP].ihl*4
		ciphertext = (scapy_packet[Raw].load[32:], scapy_packet[Raw].load[16:32], scapy_packet[Raw].load[:16])

		# z hlavicky se do pridanych dat nebere byte 8,10,11 ktere znaci checksum a ttl
		plaintext = decrypt(ciphertext, key, AES.MODE_GCM, packet.get_payload()[:8]+packet.get_payload()[9:10]+packet.get_payload()[12:ip_len])
		res_packet = IP(packet.get_payload()[:ip_len])
		res_packet = res_packet/Raw(plaintext[1:])

		res_packet[IP].proto = plaintext[0]
	    	
		# Přepočet kontrolního souètu a délky	
		del res_packet[IP].len
		del res_packet[IP].chksum
		
    		# Změna obsahu paketu na šifrovaný
		packet.set_payload(bytes(res_packet))
    		
		# Příjem šifrovaného paketu
		packet.accept()

	except:
		print ("Kontrola GMAC selhala, zahazuji paket...")
		packet.drop()

key = bytes.fromhex("7092aeb52161089b86c5b5f2824cb529e33764a1294b7ee810b8226fc650e86b")

queue = nfq()
# Odchyt paketù k dešifrování v 2. frontì pro pakety s vlastním číslem protokolu
queue.bind(2, listener)
queue.run()
