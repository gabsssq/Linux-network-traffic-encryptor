#!/bin/sh

Help()
{
   echo "Pouziti: ./install.sh [Sit_druhe_brany]"
   echo "Tvar site: x.x.x.x/y"
   echo
}

if [ $1 = "" || $1 = "-help" || $1 = "-h"]
then
Help
exit 1
fi

# Udaj pro smerovani
Route_IP=$1

# Knihovny pro kyber
git clone https://github.com/itzmeanjan/kyber.git
(cd kyber && git submodule update --init)

# Knihovny pro AES
wget https://www.cryptopp.com/cryptopp870.zip
unzip -aoq cryptopp870.zip -d cryptopp
(cd cryptopp && make)
(cd cryptopp && make install)

git clone https://github.com/gabsssq/sifrator.git

sudo ip tuntap add name tun0 mode tun
sudo ip link set tun0 up
sudo ip addr add 192.168.1.1 peer 192.168.1.2 dev tun0

echo "1" > /proc/sys/net/ipv4/ip_forward
ip route add $Route_IP via 192.168.1.2

g++ -std=c++20 -I /usr/local/include/ -I ../kyber/include/ -I ../kyber/subtle/include/ -I ../kyber/sha3/include/ ../sifrator/sifrator.cpp  /usr/local/lib/libcryptopp.a -o sifrator.exe
