#!/bin/bash
if [ "$USER" != "root" ]; then
	echo "Installation must be run as root!"
	exit
fi;

mkdir -p /etc/intrusive/rules /usr/share/intrusive/doc /var/run/intrusive /usr/share/intrusive/scripts

cp -rv README TODO LICENSE /usr/share/intrusive/doc/

echo "127.0.0.1">/etc/intrusive/excluded_hosts_list

cp -v  ./intrusive/etc/intrusive/rulefiles /etc/intrusive/rulefiles

cp -rv ./intrusive/etc/intrusive/rules/* /etc/intrusive/rules/

cp -rv ./config /etc/intrusive/config

cp -rv intrusive/usr/share/intrusive/* /usr/share/intrusive

touch /var/run/intrusive/intrusive.shun

cp -rv intrusive.pl intrusive_led.py /usr/sbin

cp intrusive_audit2allow.pl /usr/share/intrusive/scripts/

cp ./intrusive-rc.sh /etc/init.d/intrusive

chmod -R 700 /etc/intrusive /var/run/intrusive /usr/sbin/intrusive.pl /etc/init.d/intrusive
chmod -R 600 /etc/intrusive/config /etc/intrusive/rules/* /etc/intrusive/rulefiles
chmod -R 755 /usr/share/intrusive

echo "Installation complete"

