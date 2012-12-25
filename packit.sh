#!/bin/bash
if [ -d ./intrusive ]; then
 rm -rf ./intrusive
fi;
mkdir -p ./intrusive/{/etc/intrusive/rules,/usr/share/intrusive/doc,/var/run/intrusive}
mkdir -p ./intrusive/etc/init.d ./intrusive/usr/sbin
mkdir ./intrusive/usr/share/intrusive/scripts
cp -rv /usr/share/intrusive/* ./intrusive/usr/share/intrusive
cp -rv Intrusive2.odp README TODO LICENSE ./intrusive/usr/share/intrusive/doc/
echo "127.0.0.1">./intrusive/etc/intrusive/excluded_hosts_list
cp -v /etc/intrusive/rulefiles ./intrusive/etc/intrusive/rulefiles
cp -rv /etc/intrusive/rules/* ./intrusive/etc/intrusive/rules/
cp -rv ./config ./intrusive/etc/intrusive/config
touch ./intrusive/var/run/intrusive/intrusive.shun
cp intrusive.pl ./intrusive/usr/sbin
cp intrusive_audit2allow.pl ./intrusive/usr/share/intrusive/scripts/
chown -R root:root ./intrusive/
chmod -R 700 ./intrusive/
cp ./intrusive-rc.sh ./intrusive/etc/init.d/intrusive
if [ -f "intrusive.tar.bz2" ]; then
	rm -vf intrusive.tar.bz2
fi;
tar -cf intrusive.tar intrusive
bzip2 intrusive.tar && echo `date` "	intrusive.tar.bz2 ready."