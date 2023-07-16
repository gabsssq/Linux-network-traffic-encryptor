# Linux network traffic encryptor

## Overview 
This repository contains trial implementation of IPv4 network traffic encryption using quantum resistant algorithms.
This encryptor is meant to be used for creation of encryption gateways.

Usage of encryptor for other than testing purposes is currently highly discouraged.

## Encryption
Traffic is encrypted on virtual interface using algorithm AES-256 GCM (Used implementation: https://www.cryptopp.com/release870.html).
Key for AES is derived from QKD and PQC keys.

QKD key can be obtained from REST API of real QKD system or attached simulator.
PQC key is established using algorithm Kyber-512 (Used implementation: https://github.com/itzmeanjan/kyber/tree/master).

Encrypted/unencrypted traffic is distinguished by UDP port - encrypted traffic is sent to specific port.
Network traffic is encrypted on packet-by-packet basis in tunnel mode - this means, that every packet is expanded by 60 bytes (16 B nonce, 16 B MAC tag, 20 B new IPv4 address, 8 B UDP header).

Encryptor performs rekey after 200 000 encrypted messages.

## Encryptor installation
Installation script install.sh can be used for installation on Debian and Debian-based Linux distributions.

```bash
git clone https://github.com/gabsssq/sifrator.git
cd sifrator 
chmod +x install.sh
./install.sh [IP address of other encryption gateway]
```

## QKD simulator installation
```bash
git clone https://github.com/gabsssq/sifrator.git
cd sifrator 
chmod +x install_QKD.sh
./install_QKD.sh
```

## Usage
Gateways:
Encryptor is divided into 2 parts - server and client.
1st Gateway (server):
```bash
./sifrator_server [local IP address of QKD system]
```

2nd Gateway (client):
```bash
./sifrator_client [local IP address of QKD system] [IP address of server gateway]
```

Endpoints:
As a result of packet expansion due to traffic encryption there is high probability, that final packet size will be higher than network MTU.
Because of this reason must be MTU on endpoints lowered by 60 bytes.

```bash
ip link set [interface] mtu [MTU value]
```

MTU value should be typically lowered to 1440 bytes, considering most networks have MTU of 1500 bytes.

## Testing
For testing purposes, we created virtual network consisting of 2 gateways and 2 endpoints using 8 thread processor. Network topology can be seen below.

![alt text](https://github.com/gabsssq/sifrator/blob/main/DP-topologie.drawio.png?raw=true)

Endpoints were used to simulate QKD system and were given 1 thread each. Gateways were given 2 threads each.

## Performance
Methodology:
Goal of the measurement was to find out average transmission speed, using file transfer.
Selected file sizes were 1 MB, 500 MB, 1 GB, 5 GB. Every file was transfered 15 times.
Measurement was divided into 3 parts - no encryption, encryption with rekeying, encryption without rekeying.


Results:
Encryption | 1 MB [mbps] | 500 MB [mbps] | 1 GB [mbps] | 5 GB [mbps]
--- | --- | --- | --- | ---
No encryption | 435,4 | 499,8 | 476 | 458,6
Rekeying | 162,7 | 142,6 | 140,3 | 140,6
No rekeying | 162,7 | 144 | 145,3 | 145,8

Whole measurement was performed on processor Intel Core i7 1065G7 Ice Lake.
