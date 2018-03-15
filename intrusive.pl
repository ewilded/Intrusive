#!/usr/bin/perl
# Intrusive 2 coded by ewilded
# This software is licensed under the General Public License version 3 (see LICENSE)

use strict; 
use Fcntl 'O_RDONLY';
use Fcntl 'SEEK_END';
use Time::Local;
use Digest::MD5 qw(md5_hex);

## CONFIG SECTION
my %conf;
open(CONF,'</etc/intrusive/config') or die("No configuration file /etc/intrusive/config available. Exiting.");

while(my $line=<CONF>)
{
	next if($line=~/^#/);
	next if($line=~/^\s+$/);
	chomp($line);
	$line=~s/\s*$//;
	$conf{$1}=$2 if($line=~/(\w+)\s*=\s*(.*)$/);
}
close(CONF);

my @mail_alert_addrs=split(/\s+/,$conf{'mail_addrs'}) if($conf{'mail_addrs'} ne undef);

#my @SMS_numbers=split(/\s+/,$conf{'SMS_nrs'}) if($conf{'SMS_nrs'} ne undef);
# implement later ;]


my @curr_mail_addrs=();
my @rules=();
my %excluded_hosts;
my %banned_ips;
my $log_fh;
my @children=();
my $last_alert;
my %previous_log_time;
my @alert_buff=();
my $last_alert_repeat_cnt=0;
my $last_activity=0;
my $events_buffered_cnt=0;
$|=1;

open(PIDFILE,">$conf{pidfile}");
print PIDFILE $$;
close(PIDFILE);
sub destructor
{
	my $msg=shift;
	&logme($msg) if($msg);
	&logme("Exiting.");
	kill 9,@children;
	close($log_fh);
	unlink($conf{lock_file});
	unlink($conf{alert_lock});
	unlink($conf{pidfile});
	exit 0;
}
sub load_rules
{
	my $rule_file=shift;
	print "Loading: $rule_file\n";
	my $cnt=0;
	chomp($rule_file);
	if(! -f $rule_file)
	{
		&logme("[ERROR] $rule_file does not exist.");
		return;
	} 
	open(RULES,"<$rule_file") or destructor("Could not load rule file $rule_file, exiting!");
	while(<RULES>)
	{ 
		my $rule_string=$_; ## path from rulefiles
		chomp($rule_string);
		# ok, now let's split this according to our rulefiles format
		# preg:date_format_backreference:treshold_overall:treshold_per_host:policy
		if(!($rule_string=~/^(.*):(.*?):(.*?):(.*?):(.*?)$/))
		{
			&logme("$rule_string is not compliant with my format (see README - RULE FILES FORMAT)");
			next;
		}
		my $pcre=$1;
		my $date_backreference=$2;
		my $treshold_per_host=$4;
		my $treshold_overall=$3;
		my $policy=$5;
		# self test:
		## if any regular expression is bad, script will exit immediately after match try
		#print "[SELF-TEST] $pcre\n";
		"foo"=~/"^$pcre$/; #"
		push(@rules,{preg=>$pcre,date_backreference=>$date_backreference,treshold_per_host=>$treshold_per_host,treshold_overall=>$treshold_overall,policy=>$policy}); ## array of hashes, hehe
			$cnt++;
	}
	close(RULES);
	&logme("Done. $cnt rules loaded.");
}
sub monitor_log 	## READY
{
	my $PID=fork;	
	return $PID if($PID);
	my $log_file=shift;
	my $rule_path=shift;
	my $alert_type=shift;
	my $mail_addr=shift;
	my $sound_path=shift;
	print "[DEBUG] sound_path: $sound_path\n" if($conf{debug});	
	my $treshold_overall=shift;  ## this is inherited if the rule's treshold is undef
	my $treshold_per_host=shift; ## this is inherited if the rule's treshold is undef
	my $policy=shift; # enforce/permissive
	print "[DEBUG] POLICY loaded:$policy\n" if($conf{debug});
	my %events_overall;
	my %events_per_host; ## here we keep the time information - it's just the timestamp of the last event, based on this and current timestamp we calculate new rate, if it reaches the limit - we react
	chomp($log_file);
	if(! -f $log_file)
	{
		&logme("[ERROR] $log_file does not exist, child exiting.");
		exit;
	}
   # log_path:rule_path:treshold_overall:treshold_per_host:e-mail:sound
   # log_path and rule_path are mandatory
	&load_rules($rule_path);
	sysopen LOG,$log_file,O_RDONLY;
	sysseek(LOG,0,SEEK_END); 
	my $buff='';
	my $bytes_read=0;
	my $last_chunk='';	
	my %last_time_diff;
	my $IP;
	my $limit_reached=0;
	
	read_log:
	if($buff&&$bytes_read)
	{
		if(!($buff=~/\n$/))
		{
			$buff=~/([^\n]+)$/;
			$last_chunk=$1;
		}
		else
		{
			$last_chunk='';
		}
		my @lines=split(/\n/,$buff);
		for(my $i=0;$i<@lines;$i++)
		{
			$IP='';
			my $line=$lines[$i];
			while($line=~/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g&&$IP eq '')
			{
				print "[DEBUG-IP] - checking $1\n" if($conf{debug});
				$IP=$1 if(!check_friendly_ip($1));
			}
			## that's why by default we don't block IP-s pulled out from unknown lines (pure anomalies, no norm-pregs, no tresholds)
			last if($i==scalar(@lines)-1&&$last_chunk);
			my $row_suspected=1; ## default policy
			my $preg;
			my $preg_catched=0;
			for(my $i=0;$i<scalar(@rules);$i++)
			{
				$preg=$rules[$i]{preg};
				$preg="^$preg".'$';
				my $date_backref='';
				print "[PREG-CORE-DEBUG] matching $line with $preg\n" if($conf{debug});
				if(!($line=~/$preg/))
				{
					print "[NO]\n" if($conf{debug});
					next;
				}
				else
				{
					print "[YES!!!]\n" if($conf{debug});
					$preg_catched=1;
					$policy=$rules[$i]{policy} if($rules[$i]{policy} ne undef && $rules[$i]{policy} ne '');
					if($rules[$i]{date_backreference} and $IP ne undef) ## a string of form \$\d-\$\d-\$\d
					{
						print "backref: ".$rules[$i]{date_backreference}." and IP-s: $IP\n" if($conf{debug});
						my @date_parts;
						$date_parts[0]=$1;
						$date_parts[1]=$2;
						$date_parts[2]=$3;
						$date_parts[3]=$4;
						$date_parts[4]=$5;
						$date_parts[5]=$6;
						if(!($rules[$i]{date_backreference}=~/^\d-\d-\d-\d-\d-\d$/))
						{
							&logme("[ERROR] ".$rules[$i]{date_backreference}." is not a valid backreference format definition for date! Ignoring this one.");
							$date_backref='';
						}
						else
						{
							$date_backref=$rules[$i]{date_backreference};
						}
						my @date_string_map=split('-',$date_backref);
						my @date_new_string=('','','','','','');
						my $i=0;
						foreach my $date_part(@date_string_map)
						{
							$date_new_string[$date_part-1]=$date_parts[$i];
							$i++;
						}
						my $date_final_string=join('-',@date_new_string);
						print "Calculating time difference from the date (date_string: $date_final_string - $date_backref).\n" if($conf{debug});
						my @months=('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec');
						for(my $i=0;$i<scalar(@months);$i++) 
						{ 
							my $month=$i+1;
							$date_final_string=~s/$months[$i]/$month/i;
						}
						print "Calculated, date_string: $date_final_string .\n" if($conf{debug});
						if($date_final_string=~/(\d{4})-(\d{1,2})-(\d{1,2})-(\d{2})-(\d{2})-(\d{2})/)
						{
							my $log_year=$1;
							my $log_month=$2;
							my $log_day=$3;
							my $log_hour=$4;
							my $log_minute=$5;
							my $log_second=$6;
							my $log_time=timelocal($log_second,$log_minute,$log_hour,$log_day,$log_month-1,$log_year);
							if($previous_log_time{$IP} eq undef)
							{
								$previous_log_time{$IP}=$log_time; ## first event for this host
								$last_time_diff{$IP}=0;
								$row_suspected=0;
								print "First event encountered.\n" if($conf{debug});
								goto after_suspicion;
							}
							else
							{ 
								my $time_diff=$log_time-$previous_log_time{$IP};
								$previous_log_time{$IP}=$log_time;
								if($time_diff eq $last_time_diff{$IP})
								{
										print "[DEBUG] $time_diff == $last_time_diff{$IP}, automated request  from $IP detected!\n" if($conf{debug});
										if($time_diff eq 0)
										{
											print "False alarm probably, to short time window (time_diff = 0).\n" if($conf{debug});
											$row_suspected=0;
											goto after_suspicion;
										}
										$row_suspected=1;
										goto suspect_row; 
								}
								else
								{
										print "[DEBUG] $time_diff != $last_time_diff{$IP}, automated request from $IP detected!\n" if($conf{debug});
								}
								$last_time_diff{$IP}=$time_diff;
							}
						}				
						else
						{
							&logme("Invalid date format: $date_final_string.");
						}
					}
					### ok, now check the time conditions
					$rules[$i]{'treshold_overall'}=$treshold_overall if($rules[$i]{'treshold_overall'} eq undef);
					$rules[$i]{'treshold_per_host'}=$treshold_per_host if($rules[$i]{'treshold_per_host'} eq undef);
					if($rules[$i]{'treshold_overall'}==-1)
					{
						print "[SUSPECT-DEBUG] goto after susp (-1, this is normal).\n" if($conf{debug});
						$row_suspected=0;
						goto after_suspicion;						
					}
					if($rules[$i]{'treshold_overall'}==0)
					{
						print "It's equal to 0, row is suspected.\n" if($conf{debug});
						$row_suspected=1;
						goto suspect_row;
					}
					my $right_now=time;
					my $hash=md5_hex($rules[$i]{'preg'});
					## ok, let's make it new way
					my $minutes=1;
					my $max_treshold;
					$events_overall{$hash}{$right_now}=1;
					if($rules[$i]{'treshold_overall'}<1) 
					{
						$minutes=$minutes*(1/$rules[$i]{'treshold_overall'});
						$max_treshold=1;
					}
					else
					{
						$max_treshold=$rules[$i]{'treshold_overall'};
					}
					my $counter=0;
					$limit_reached=0;
					foreach my $last_time(keys %{$events_overall{$hash}})
					{
						if($right_now-$last_time>$minutes*60) 
						{
							print "Unsetting $last_time.\n" if($conf{debug});
							$events_overall{$hash}{$last_time}=undef;
							next;
						}
						else
						{
							$counter++;
							print "Counting $last_time... ($counter events in $minutes minutes).\n" if($conf{debug});
						}
					}
					if($max_treshold<$counter)
					{
						$limit_reached=$counter;
						print "$max_treshold le $counter encountered, suspecting.\n" if($conf{debug}); 
						$row_suspected=1;
						goto suspect_row;
					}
					else
					{
						print " $counter lt $max_treshold, not suspecting.\n" if($conf{debug});
						$row_suspected=0;
					}
					#### THE SAME FOR PER IP
					if($IP eq undef)
					{
						$row_suspected=0;
						goto after_suspicion; 
					}
					$events_per_host{$hash}{$IP}{$right_now}=1;
					if($rules[$i]{'treshold_per_host'} eq -1)
					{
						$row_suspected=0;
						goto after_suspicion;
					}
					if($rules[$i]{'treshold_per_host'} eq 0)
					{
						$row_suspected=1;
						$preg_catched=1;
						goto suspect_row;
					}
					$minutes=1;
					$events_overall{$hash}{$IP}{$right_now}=1;
					if($rules[$i]{'treshold_per_host'}<1) 
					{
						$minutes=$minutes*(1/$rules[$i]{'treshold_per_host'});
						$max_treshold=1;
					}
					else
					{
						$max_treshold=$rules[$i]{'treshold_per_host'};
					}
					$counter=0;
					foreach my $last_time(keys %{$events_per_host{$hash}{$IP}})
					{
						if($right_now-$last_time>$minutes*60) 
						{
							print "Unsetting (per host $IP) $last_time.\n" if($conf{debug});
							$events_per_host{$hash}{$last_time}=undef;
							next;
						}
						else
						{
							$counter++;
							print "Counting (per host $IP) $last_time... ($counter events in $minutes minutes).\n" if($conf{debug});
						}
					}
					if($max_treshold<$counter)
					{
						print "$max_treshold<$counter encountered, suspecting ($IP).\n" if($conf{debug});
						$limit_reached=$counter;
						$row_suspected=1;
						goto suspect_row;
					}
					else
					{
						print "$counter lt $max_treshold, not suspecting ($IP).\n" if($conf{debug});
						$row_suspected=0;
					}
					goto after_suspicion;
					suspect_row:
					$row_suspected=1;
					after_suspicion:
					print "[PREG DEBUG] $preg with $line (is suspected: $row_suspected)\n" if($conf{debug});
					goto after_all;
				}
			} # end of foreach (rules)
			after_all:
			print "[PREG DEBUG2] $preg (is suspected: $row_suspected, policy:$policy, alert_type: $alert_type)\n" if($conf{debug});
			if($row_suspected eq 1)
			{
				push(@alert_buff,{line=>$line,IP=>$IP,preg=>$preg,alert_type=>$alert_type,mail_addr=>$mail_addr,sound_path=>$sound_path,preg_catched=>$preg_catched,limit_reached=>$limit_reached,policy=>$policy,block_performed=>0,log_file=>$log_file});
				$limit_reached=0;
				$buff=''; ## clear the buffer after alert
			}
		} # end of for (lines)
	} ## end of if(buff)
	if(scalar(@alert_buff)>0)
	{
		my $d=time-$last_activity;	# when was the previous event fetched
		if(($d>20||$events_buffered_cnt >= 3)&& &alert() eq 1) ### give any further events 20 more seconds to get collected, to avoid splitting related log entries occurring in nearly same time between separate alerts, but do not withold for more than 3 messages either (otherwise one could keep generating an event every 19 seconds and therefore keep Intrusive from alerting for ever, stuffing all the events into the buffer)
		{
			$events_buffered_cnt=0;			
			# zero the counter, as the second condition indicates that we have just sent out an alert			
		}
		else
		{
			print "Holding stuff because last activity was less than 20 seconds ago ($d seconds ago) or events_buffered_cnt ($events_buffered_cnt) < 3" if($conf{debug});
			sleep(1);
			$events_buffered_cnt++;
		}	
	}
 	$buff='';
	$bytes_read=sysread LOG,$buff,1024;
	$last_activity=time if($bytes_read>0);
	$buff="$last_chunk$buff";
	select(undef,undef,undef,0.1);
	goto read_log;
}
sub send_mail 	## READY 
{
	my $content=shift;
	chomp($content);
	my $hostname=`hostname`;
	chomp($hostname);
	my $subject='Intrusive2 alert on '.$hostname;
	my $title=$subject;
	open(F,">$conf{alert_buff}");
	chmod 0600, $conf{alert_buff};		# prevent info disclosure
	print F "Subject:$subject\nDetails:\n$content\n";
	foreach my $mail_alert_addr(@mail_alert_addrs)
	{
 		`sendmail -f $conf{mail_from} $mail_alert_addr<$conf{alert_buff}`;
 	}
 	close(F); 	
 	print "[DEBUG] mail sent!\n" if($conf{debug});
 	@curr_mail_addrs=();
}
sub alert	## READY
{
	my $time_diff=0;
	my $alert_now=1;
	if( -f $conf{alert_lock})
	{
	 	print "[DEBUG] alert held due the existence of alert lock file ($conf{alert_lock}).\n" if($conf{debug});
	 	$alert_now=0;
	}
	elsif(-f $conf{alert_marker})
	{
		my $time=0;
		my $mtime=0;
		my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks)=stat($conf{alert_marker});
	 	$time=time;
	 	$time_diff=$time-$mtime;
	 	if($time_diff<$conf{alert_repeat_delay})
	 	{
	 		print "[DEBUG] alert held due the repeat frequency condition (last alert performed $time_diff seconds ago, which is less than $conf{alert_repeat_delay}).\n" if($conf{debug});
	 		$alert_now=0;	 		
	 	}
	 }
	my $sound_path;
	my $mail_addr;
	my $alert_string='';
	my %alert_types;
	print "There are ".scalar(@alert_buff)." alerts to raise (INSIDE OF ALERT FUNCTION)\n" if($conf{debug});
	for(my $i=0;$i<scalar(@alert_buff);$i++)
	{	
		my $content=$alert_buff[$i]{line};
		my $IP=$alert_buff[$i]{IP};
		my $rule_preg=$alert_buff[$i]{rule_preg};
		my $alert_type=$alert_buff[$i]{alert_type};
		$alert_types{$alert_type}=1;
		$mail_addr=$alert_buff[$i]{mail_addr};
		$sound_path=$alert_buff[$i]{sound_path};
		my $preg_catched=$alert_buff[$i]{preg_catched}; # we know whether or not it's a pure anomaly
		my $limit_reached=$alert_buff[$i]{limit_reached};
		my $policy=$alert_buff[$i]{policy};
		if($IP ne undef && $policy eq 'enforcing' && $alert_buff[$i]{block_performed} eq 0)
		{
			if(!$preg_catched||!$conf{ban_anomalies})
			{
				&logme("$IP was pulled out from unidentified string, ban_anomalies option is set to 0, avoiding traffic blocking.");
			}
			else
			{
				if($IP ne undef && check_friendly_ip($IP))
				{
					&logme("$IP is friendly! Block cancelled."); 
				}
				else
				{ 
					if($banned_ips{$IP} eq undef)
					{
						`iptables -I INPUT -s $IP -j DROP`;
						$banned_ips{$IP}=1;
						&logme("[BANNED] $IP");
						open(EVIL_HOSTS,">>$conf{evil_hosts}");
						print EVIL_HOSTS "$IP\n";
						close(EVIL_HOSTS);
					}
					else
					{
						&logme("[ALREADY BANNED] $IP");
					}
				}
			}
			$alert_buff[$i]{block_performed}=1;
		}		
		next if(!$alert_now);
		
		$sound_path=$conf{sound_alert} if($sound_path eq undef||!$sound_path);
		@curr_mail_addrs=@mail_alert_addrs;
		if($mail_addr)
		{	
			my @local_mail_addr=split(/\s+/,$mail_addr);
			foreach my $my_local_mail_addr(@local_mail_addr) 
			{
				push(@curr_mail_addrs,$my_local_mail_addr);
			}
		}
		$alert_type='both' if($alert_type eq undef||!$alert_type);
	
		if($last_alert ne undef && $last_alert eq $rule_preg)
		{
			$last_alert_repeat_cnt++;
		}
		else
		{
			if($last_alert_repeat_cnt>0)
			{
				&logme("[ALERT] last message repeated $last_alert_repeat_cnt times.");
				$last_alert_repeat_cnt=0;	
			}
		}
		&logme("[ALERT] $content");
		
		$last_alert=$rule_preg;
 		### CHECK THIS SHIT ONCE AGAIN
		print "[ALERTER-BEFORE-DEBUG]\n" if($conf{debug});
		print "[ALERTER-DEBUG] no lock file present\n" if($conf{debug});
		my $alert_info='';
		if($preg_catched eq 1) 
		{
			$alert_info.="$limit_reached events per minute limit exceeded"; 
		}
		else
		{
			$alert_info.='unknown event(anomaly)';
		}
		$alert_info.=' (log file  '.$alert_buff[$i]{log_file}.')';
		my $action_taken='';
		$action_taken=" (blocked IP: $IP) " if($policy eq 'enforcing'&&$IP ne '');
		$content="$alert_info$action_taken: $content\n";
	 	$alert_string.=$content;
	} # end of foreach
	
    	return 0 if(!$alert_now);
    	my $send_buff=$alert_string;
    	@alert_buff=();
    	return 1 if(fork);
	open(F1,">$conf{alert_lock}");
	open(F2,">$conf{alert_marker}");
	close(F2);
	
	### both means mail + sound
	if($alert_types{'both'} ne undef)
	{
		 &send_mail($send_buff);
		`play $sound_path`; 
	}

	&send_mail($send_buff) if($alert_types{'mail'} ne undef);

 	if($alert_types{'sound'} ne undef)
 	{
		if($sound_path eq '')
		{
			&logme("[ERROR] Cannot play sound, no audio file path configured.");
		}
		else
		{
	   		`play $sound_path`;
			print "Playing $sound_path.\n" if($conf{debug});
		}
 	}
	if($alert_types{'LED'} ne undef)
	{
		if(!(-f $conf{'alert_flash_lock'}))
		{
			open(F3,">$conf{alert_flash_lock}");
			if(!fork())
			{
				while(-f $conf{'alert_flash_lock'})
				{
					`python /usr/sbin/intrusive_led.py`; # 2 seconds
					sleep(1);
				}
				# OK, lock has been removed, stop blinking and exit
				exit(); 
			}
		}
	}
	close(F1);
	unlink($conf{alert_lock});
	exit;
}
sub load_hosts	## READY
{
	my $cnt=0;
	&logme("Loading friendly hosts list ...");
	open(FRIENDLY_HOSTS,"<$conf{excluded_hosts}") or destructor("Could not open whitelisted hosts list $conf{excluded_hosts}, exiting!"); 
	while(<FRIENDLY_HOSTS>)
	{
		print;
		chomp;
		$excluded_hosts{$_}=1;
		$cnt++;
	}
	close(FRIENDLY_HOSTS);
	&logme("$cnt hosts loaded.");
	$cnt=0;
	&logme("Loading unfriendly hosts list ...");
	if(! -f $conf{evil_hosts})
	{
		open(EVIL_HOSTS,">$conf{evil_hosts}") or destructor("Could not create $conf{evil_hosts}, exiting!"); 
		close(EVIL_HOSTS);
	}
 	open(EVIL_HOSTS,"<$conf{evil_hosts}") or destructor("Could not open banned hosts list $conf{evil_hosts}, exiting!");
 	while(<EVIL_HOSTS>)
	{
		$cnt++;
		print;
		chomp;
		$banned_ips{$_}=1;
		if($conf{policy} eq 'enforcing')
		{
			my $exists=`iptables -L -n|grep $_`;
			if(!($exists=~/DROP/)) 
			{
				&logme("iptables -I INPUT -s $_ -j DROP");
				`iptables -I INPUT -s $_ -j DROP`;
			}
		}
	}
 	close(EVIL_HOSTS);
 	&logme("$cnt hosts loaded.");
}

#sub dump_privs 
#{
#	 my $uid = getpwnam($user);
#	 my $gid = getgrnam($group);
#	 if($uid>0&&$gid>0)
#	{
#		 $>=$uid;
#		 $)=$gid;
#		 return 1;
#	}
#	 &logme("FATAL: cannot drop privileges to the $user:$group set in the configuration, make sure they exist in the system, exiting due the security risk.");
#	 return 0;
#}
sub logme	## READY
{
	my $line=shift;
	chomp($line);
	my $dt=`date`;
	chomp($dt);
	my $content="[$dt] $line\n";
	print $log_fh $content;
	print $content;
}
sub check_ip_mask ## READY 
{	
	my $ip_to_check=shift;
	my $ip_network=shift;
	my $mask_bitlength=shift;
	$ip_network=~s/\/\d+$//;
	my @ip_bytes=split(/\./,$ip_to_check);
	my @net_bytes=split(/\./,$ip_network);
	my $j;
	my $i;
	for($i=0;$i<4;$i++) 
	{
		my $bitindex=128;
		for($j=0;$j<8;$j++) 
		{
			if((!($ip_bytes[$i]&$bitindex)&&!($net_bytes[$i]&$bitindex))||($ip_bytes[$i]&$bitindex&&$net_bytes[$i]&$bitindex&&$ip_bytes[$i]&$bitindex)) 
			{
				$bitindex>>=1;
				next;
			}
			goto s_done;
		}
	}
	s_done:
	return 1 if($i*8+$j>=$mask_bitlength);
	return 0;
}
sub check_friendly_ip 	## READY 
{
	my $ip_to_check=shift;
	foreach my $host(keys %excluded_hosts) 
	{
			print "[DEBUG] checking $host against $ip_to_check.\n" if($conf{debug});
			return "$host" if($host eq $ip_to_check);
			if($host=~/\/(\d+)/) 
			{
				print "[DEBUG] Checking bitlen $1.\n" if($conf{debug});
				my $bitlen=$1;
				if(&check_ip_mask($ip_to_check,$host,$bitlen))
				{
					print "[DEBUG] Everyone is having fun fun fun, and everyone is nice, and everyone (even $host) is friendly! :D\n" if($conf{debug}); 
					return "$host"; 
				}
			}
	}
	return 0;
}
die "Fatal, $conf{sound_alert} file not detected, make sure you've set it correctly!\n" if($conf{sound_alert} && ! -f $conf{sound_alert});

open($log_fh,">>$conf{log_file}");
chmod 0600, $log_fh;

&logme("Intrusive stared.");
if(-f $conf{lock_file})
{
	&logme("Lockfile $conf{lock_file} exists, which means other process is running or Intrusive was not shut down clean, exiting!");
	exit;
}
open(F,">$conf{lock_file}");
close(F);
&load_hosts();
open(LOG_LIST,"<$conf{rulefiles}") or destructor("Could not open list of log files locations to monitor ($conf{rulefiles}), make sure you created it, exiting!");
while(<LOG_LIST>) 
{
	 chomp;
	 next if($_=~/^#/); # skip commented lines
	 next if($_=~/^\s*$/);
	# log_path:rule_path:treshold_overall:treshold_per_host:alert_type:e-mail:sound:treshold_per_host:treshold_overall:policy
	 my ($log_file,$rule_path,$alert_type,$mail_addr,$sound_path,$treshold_per_host,$treshold_overall,$policy)=split(/:/,$_);
	 ## log_files can be a pattern
	 $treshold_per_host=$conf{treshold_per_host_default} if($treshold_per_host eq undef);
	 $treshold_overall=$conf{treshold_overall_default} if($treshold_overall eq undef);
	 $policy=$conf{policy} if($policy eq undef||$policy eq '');
	 $sound_path=$conf{sound_path} if($sound_path eq '');
	 my @log_file_paths=`ls $log_file`;
	 foreach my $log_file_path(@log_file_paths)
	 {
	   chomp($log_file_path);
	   next if($log_file_path eq '');
	 	push(@children,&monitor_log($log_file_path,$rule_path,$alert_type,$mail_addr,$sound_path,$treshold_overall,$treshold_per_host,$policy));		 
	 }
}	 
close(LOG_LIST);
$SIG{'INT'}=$SIG{'HUP'}=$SIG{'TERM'}=$SIG{'KILL'}=$SIG{'CHLD'}='destructor';
sleep;
