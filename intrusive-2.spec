Summary: Configurable logfiles real-time analyser with option of alerting and traffic blocking.
Name: intrusive
Version: 2
Release: 0
License: GPL
Group: Applications/Productivity 
Source: intrusive-2.tar.bz2
BuildRoot: /var/tmp/%{name}-buildroot

%description
Intrusive2 is a simple log-watcher written in Perl, 
with IDS, semi-IPS and anomaly detection functionality. 
It works by monitoring active log files in the realtime, 
just like tail -f. As new line appears, Intrusive compares 
it with set of user-defined rules consisting of regular 
expressions and a few settings.

%prep
%setup -q

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/sbin
mkdir -p $RPM_BUILD_ROOT/usr/man/man1
mkdir -p $RPM_BUILD_ROOT/usr/share/intrusive/{doc,scripts}
mkdir -p $RPM_BUILD_ROOT/etc/intrusive/rules
mkdir -p $RPM_BUILD_ROOT/var/run/intrusive
mkdir -p $RPM_BUILD_ROOT/etc/init.d/
mkdir -p $RPM_BUILD_ROOT/etc/cron.daily/

install -m 755 intrusive.pl $RPM_BUILD_ROOT/usr/sbin/intrusive.pl
install -m 755 intrusive $RPM_BUILD_ROOT/etc/init.d/intrusive
install -m 644 README $RPM_BUILD_ROOT/usr/man/man1/intrusive.1
install -m 644 TODO $RPM_BUILD_ROOT/usr/share/intrusive/doc/TODO
install -m 644 LICENSE $RPM_BUILD_ROOT/usr/share/intrusive/doc/LICENSE
install -m 644 README $RPM_BUILD_ROOT/usr/share/intrusive/doc/README
install -m 644 Intrusive.odp $RPM_BUILD_ROOT/usr/share/intrusive/doc/Intrusive.odp
install -m 755 intrusive_audit2allow.pl $RPM_BUILD_ROOT/usr/share/intrusive/scripts/intrusive_audit2allow.pl
install -m 644 combichrist_intruder_alert.wav $RPM_BUILD_ROOT/usr/share/intrusive/combichrist_intruder_alert.wav
install -m 644 warning.mp3 $RPM_BUILD_ROOT/usr/share/intrusive/warning.mp3
install -m 600 excluded_hosts_list $RPM_BUILD_ROOT/etc/intrusive/excluded_hosts_list
install -m 600 rulefiles $RPM_BUILD_ROOT/etc/intrusive/rulefiles
install -m 600 auth $RPM_BUILD_ROOT/etc/intrusive/rules/auth
install -m 600 messages $RPM_BUILD_ROOT/etc/intrusive/rules/messages
install -m 600 cron $RPM_BUILD_ROOT/etc/intrusive/rules/cron
install -m 600 asterisk $RPM_BUILD_ROOT/etc/intrusive/rules/asterisk
install -m 600 httpd $RPM_BUILD_ROOT/etc/intrusive/rules/httpd
install -m 600 intrusive.shun $RPM_BUILD_ROOT/var/run/intrusive/intrusive.shun
install -m 600 config $RPM_BUILD_ROOT/etc/intrusive/config
install -m 700 logrotate0 $RPM_BUILD_ROOT/etc/cron.daily/logrotate0


%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%config(noreplace) /etc/intrusive/config
%config(noreplace) /etc/intrusive/rulefiles
/usr/sbin/intrusive.pl
/usr/man/man1/intrusive.1.gz
%config(noreplace) /etc/intrusive/excluded_hosts_list
/etc/intrusive/rules/auth
/etc/intrusive/rules/asterisk
/etc/intrusive/rules/cron
/etc/intrusive/rules/httpd
/etc/intrusive/rules/messages
/etc/init.d/intrusive
/etc/cron.daily/logrotate0
/usr/share/intrusive/scripts/intrusive_audit2allow.pl
/usr/share/intrusive/combichrist_intruder_alert.wav
/usr/share/intrusive/warning.mp3
/usr/share/intrusive/doc/README
/usr/share/intrusive/doc/TODO
/usr/share/intrusive/doc/Intrusive.odp
/usr/share/intrusive/doc/LICENSE 
/var/run/intrusive/intrusive.shun