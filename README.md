Tento manuál popisuje kroky ke zprovoznění linuxového šifrátoru.

Topologie šifrátoru:

Klient (+ QKD simul) <---> Šifrovací brána 1 <---> Šifrovací brána 2 <---> Server (+ QKD simul)

1) Stáhnout a nainstalovat linuxový obraz např. z https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-11.6.0-amd64-netinst.iso
2) Nastavit adresy rozhraní, pokud není nastaveno DHCP (ifconfig [název rozhrani] [IP adresa] netmask [maska sítě])
   - pokud není dostupný ifconfig, je potřeba provést příkaz apt-get install net-tools
   - popř. použít příkaz ip address add [IP adresa/maska] dev [název rozhraní] & ip link set [název rozhraní] up
3) Stáhnout git repozitář (git clone https://github.com/gabsssq/sifrator.git)
4) cd sifrator && chmod +x install.sh && chmod +x install_QKD.sh
   
Klient a server:
1) Omezit MTU rozhraní na 1440 bytů (ifconfig [název_rozhraní] mtu 1440 up)
   - popř. ip link set [název_rozhraní] mtu 1440
2) Přidat výchozí cestu přes šifrovací bránu (ip route add 0.0.0.0/0 via [IP šifrovací brány])
   - nejspíše bude nutné odstranit současný záznam
3) Spustit skript pro instalaci QKD simulátoru (./install_QKD.sh)

Šifrovací brány:
1) Spustit skript pro instalaci šifrátoru (./install.sh [IP sítě druhé brány])
2) Spustit šifrátor v režimu server na 1. bráně (./sifrator_server [IP QKD simulatoru - IP Klienta])
3) Spustit šifrátor v režimu client na 2. bráně (./sifrator_client [IP QKD simulatoru - IP Serveru] [IP druhé šifrovací brány])
