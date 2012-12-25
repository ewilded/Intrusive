#!/usr/bin/perl
## Intrusive2's audit2allow equivalent
## generates base for rules based on all lines of log files supplied on the stdin (it's just intended to speed up the process of creating the rules, its output still requires your tuning (for instance, it doesn't know whether or not 'Apr' is a constant or should be replaced with \w{3}, you have to make such decisions yourself, it just basically escapes all PCRE special characters to avoid confusion when content is used as a part of regular expression)
use strict;
use List::MoreUtils qw/uniq/;
my @rules;
while(my $logfile=<STDIN>)
{
	chomp($logfile);
	if( -f $logfile)
	{
		open(F,"<$logfile");
		while(my $line=<F>)
		{
			chomp($line);
			my $oldline="#$line";
			$line=~s/\+/\\+/g;
			$line=~s/\./\./g;
			$line=~s/\//\\\//g;
			$line=~s/\*/\\*/g;
			$line=~s/\?/\\?/g;
			$line=~s/\[/\\[/g;
			$line=~s/\]/\\]/g;
			$line=~s/\^/\\^/g;
			$line=~s/\(/\\(/g;
			$line=~s/\)/\\)/g;
			$line=~s/\d+/\\d+/g;
			$line=~s/\./\\./g;
			# . \ + * ? [ ^ ] $ ( ) { } = ! < > | : -
			push(@rules,$line);
		}
		close(F);
	}
}
my @rules_uniq=uniq @rules;
foreach (@rules_uniq) { print $_,"::-1:-1:", "\n"; }
