#!/bin/sh

Help()
{
   echo "Pouziti: ./install.sh [Sit_druhe_brany]"
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

g++ -std=c++20 -I /usr/local/include/ -I ./kyber/include/ -I ./kyber/subtle/include/ -I ./kyber/sha3/include/ sifrator.cpp  /usr/local/lib/libcryptopp.a -o sifrator.exe

