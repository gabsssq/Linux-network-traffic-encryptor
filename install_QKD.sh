#!/bin/sh
apt-get install apache2
apt-get install php7.4
a2dismod mpm_event
a2enmod php7.4
systemctl restart apache2
mkdir /var/www/html/klic
mkdir /var/www/html/ID
cp index-klic.php /var/www/html/klic/index.php
cp index-ID.php /var/www/html/ID/index.php
(cd /var/www/html && fallocate -l 1G test)
