#!/usr/bin/env python
# Reads the PAUSE button using interupts and sets the LED
# Pin table at https://github.com/beagleboard/beaglebone-blue/blob/master/BeagleBone_Blue_Pin_Table.csv

# Import PyBBIO library:
import Adafruit_BBIO.GPIO as GPIO
import time

button="P8_9"  # PAUSE=P8_9, MODE=P8_10
LED   ="USR3"

# Set the GPIO pins:
GPIO.setup(LED,    GPIO.OUT)
GPIO.setup(button, GPIO.IN)

print("Running...")

while True:
  state = GPIO.input(button)
  GPIO.output(LED, state)
  
  GPIO.wait_for_edge(button, GPIO.BOTH)
  print("Pressed")