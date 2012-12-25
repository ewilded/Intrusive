#!/bin/sh
#
# Intrusive2 Red-Hat like startup script coded by ewilded
#
# description: Starts and stops the Intrusive2 log monitoring tool
#
. /etc/rc.d/init.d/functions
RETVAL=0
PIDFILE=/var/run/intrusive.pid
start()
{
	nohup perl /usr/sbin/intrusive.pl > /dev/null &
}
stop()
{
	kill `cat $PIDFILE`
	RETVAL=$?
	rm -rf $PIDFILE	
}
case "$1" in
  start)
        start
        ;;
  stop)
        stop
        ;;
  status)
  		  status intrusive
  		  ;;
  restart)
        stop
        start
        ;;
  *)
        echo $"Usage: $0 {start|stop|restart|status}"
        RETVAL=3
esac
exit $RETVAL