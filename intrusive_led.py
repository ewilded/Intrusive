import RPi.GPIO as GPIO
import time
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
GPIO.setup(4,GPIO.OUT)


#print "LED on"
GPIO.output(4,GPIO.HIGH)
time.sleep(1)
#print "LED off"
GPIO.output(4,GPIO.LOW)
time.sleep(1)
