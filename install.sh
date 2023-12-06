#!/bin/sh

Help()
{
   echo "Usage: ./install.sh [Other gateway network]"
   echo "Network format: x.x.x.x/y"
   echo
}

if [ $# -lt 1 ] || [ $1 = "-help" ] || [ $1 = "-h" ]
then
Help
exit 1
fi

# Install dependencies
cat requirements.txt | sudo xargs apt install -y

# Add routing information
Route_IP=$1

# Install Kyber library
git clone https://github.com/gabsssq/kyber.git
(cd kyber && git submodule update --init)

# Install AES library
wget https://www.cryptopp.com/cryptopp870.zip
unzip -aoq cryptopp870.zip -d cryptopp
(cd cryptopp && sudo make)
(cd cryptopp && sudo make install)

sudo ip tuntap add name tun0 mode tun
sudo ip link set tun0 up
sudo ip addr add 192.168.1.1 peer 192.168.1.2 dev tun0

echo "1" | sudo tee /proc/sys/net/ipv4/ip_forward
sudo ip route add $Route_IP via 192.168.1.2
chmod +x sym-ExpQKD
g++ -std=c++20 -O3 -pthread -I /usr/local/include/ -I ./kyber/include/ -I ./kyber/subtle/include/ -I ./kyber/sha3/include/ encryptor_server.cpp  /usr/local/lib/libcryptopp.a -o encryptor_server
g++ -std=c++20 -O3 -pthread -I /usr/local/include/ -I ./kyber/include/ -I ./kyber/subtle/include/ -I ./kyber/sha3/include/ encryptor_client.cpp  /usr/local/lib/libcryptopp.a -o encryptor_client
touch key
touch keyID
