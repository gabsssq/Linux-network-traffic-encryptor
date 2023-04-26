#!/usr/bin/python3
from scapy.all import *
from Cryptodome.Cipher import AES
import fcntl
from multiprocessing import Process

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

     
def listener(packet):
	scapy_packet = IP(packet)
	ip_len = scapy_packet[IP].ihl * 4

    # Dešifrovaní paketu s nahrazením cílové adresy a protokolu
	if (scapy_packet[IP].proto == 99):
		try:
			ciphertext = (scapy_packet[Raw].load[32:], scapy_packet[Raw].load[16:32], scapy_packet[Raw].load[:16])
			plaintext = decrypt(ciphertext, key, AES.MODE_GCM)
			res_packet = IP(bytes(scapy_packet)[:ip_len])
			res_packet = res_packet/Raw(plaintext[5:])
			res_packet[IP].proto = plaintext[4]
			res_packet[IP].dst = str(plaintext[0])+"."+str(plaintext[1])+"."+str(plaintext[2])+"."+str(plaintext[3])

			del res_packet[IP].len
			del res_packet[IP].chksum

			return(bytes(res_packet))

		except:
			print ("Desifrovani selhalo")
	
	
    # Šifrovaní paketu s nahrazením cílové adresy a protokolu
	else:

		ciphertext = encrypt(bytes(scapy_packet)[16:20]+bytes(scapy_packet)[9:10]+bytes(scapy_packet)[ip_len:], key, AES.MODE_GCM)

		res_packet = IP(bytes(scapy_packet)[:ip_len])
		res_packet = res_packet/(ciphertext[2]+ciphertext[1]+ciphertext[0])
		res_packet[IP].proto = "mujPr"
		res_packet[IP].dst="192.168.1.2"
		del res_packet[IP].len
		del res_packet[IP].chksum
		return bytes(res_packet)

    # Spuštění šifrování a dešifrování
def sifruj():
	while True:
		packet =  tun.read(2048)
		packet = listener(packet)
		try:
			tun.write(bytes(packet))
		except:
			print ("Kontrola GMAC selhala, zahazuji paket...")

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
	
    # Vytvoření kopie procesu pro využití více CPU
    p = Process(target=sifruj, args=())
	p.start()
	sifruj()
