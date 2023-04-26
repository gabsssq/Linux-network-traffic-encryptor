#!/bin/bash
ENCint=$1
DECint=$2
CurrDIR=$(pwd)

cat apt-req.txt | xargs apt install -y
pip install -r requirements.txt

echo "mujPr 150" >> /etc/protocols

iptables -I FORWARD -i $1 -j NFQUEUE --queue-num 1
iptables -I FORWARD -i $2 -j NFQUEUE --queue-num 2 -p 150

touch /etc/systemd/system/xtumapENC.service
echo  "[UNIT]
Description=sifrovani
After=multi-user.target

[Service]
type=simple
Restart=always
ExecStart=/usr/bin/python3 $CurrDIR/ipencrypt.py

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/xtumapENC.service

touch /etc/systemd/system/xtumapDEC.service
echo  "[UNIT]
Description=desifrovani
After=multi-user.target

[Service]
type=simple
Restart=always
ExecStart=/usr/bin/python3 $CurrDIR/ipdecrypt.py

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/xtumapDEC.service

systemctl daemon-reload
systemctl enable xtumapENC.service
systemctl enable xtumapDEC.service
systemctl start xtumapENC.service
systemctl start xtumapDEC.service
